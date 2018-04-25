{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase       #-}
module Hummingbird.Administration.Server ( run ) where
--------------------------------------------------------------------------------
-- |
-- Module      :  Hummingbird.Administration.Server
-- Copyright   :  (c) Lars Petersen 2017
-- License     :  MIT
--
-- Maintainer  :  info@lars-petersen.net
-- Stability   :  experimental
--------------------------------------------------------------------------------

import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception                   (SomeException, bracket,
                                                      catch, try)
import           Control.Monad                       (forever, void, when,
                                                      (>=>))
import           Data.Aeson                          (FromJSON)
import qualified Data.Binary                         as B
import qualified Data.Binary.Get                     as B
import qualified Data.Binary.Put                     as B
import           Data.Bits
import qualified Data.ByteString                     as BS
import qualified Data.IntMap                         as IM
import qualified Data.IntSet                         as IS
import qualified Data.Text                           as T
import qualified Data.Text.Encoding                  as T
import           System.Exit
import qualified System.FilePath                     as FilePath
import           System.IO                           (hPutStrLn, stderr)
import qualified System.Log.Logger                   as LOG
import qualified System.Posix.Files                  as Files
import qualified System.Socket                       as S
import qualified System.Socket.Family.Unix           as S
import qualified System.Socket.Protocol.Default      as S
import qualified System.Socket.Type.Stream           as S

import qualified Network.MQTT.Broker                 as Broker
import           Network.MQTT.Broker.Authentication  (Authenticator,
                                                      AuthenticatorConfig,
                                                      getLastException)
import qualified Network.MQTT.Broker.Session         as Session
import qualified Network.MQTT.Trie                   as R

import qualified Hummingbird.Administration.Request  as Request
import qualified Hummingbird.Administration.Response as Response
import qualified Hummingbird.Configuration           as C
import           Hummingbird.Internal

run :: (Authenticator auth, FromJSON (AuthenticatorConfig auth), Show (AuthenticatorConfig auth)) => Hummingbird auth -> IO a
run hum = do
    config <- getConfig hum
    let path = C.adminSocketPath $ C.admin config
    let directory = FilePath.takeDirectory path
    -- Check parent directory permissions. The parent directory must only be
    -- accessible by owner and group.
    directoryMode <- Files.fileMode <$> Files.getFileStatus directory
    when (directoryMode .&. (Files.otherReadMode .|. Files.otherWriteMode .|. Files.otherExecuteMode) /= 0) $ do
      hPutStrLn stderr $ show directory ++ " must not be world-accessible!"
      exitFailure
    -- Make sure the socket file does not already exist.
    -- Unlink first and log when existing.
    exists <- Files.fileExist path
    when exists $ do
      LOG.warningM "Administration" $ show path  ++ " already exists. Unclean shutdown or another instance running? Will unlink existing socket now."
      Files.removeLink path

    case S.socketAddressUnixPath (T.encodeUtf8 $ T.pack path) of
      Nothing -> do
        hPutStrLn stderr $ "Invalid path: " ++ C.adminSocketPath (C.admin config)
        exitFailure
      Just addr -> bracket
        ( S.socket :: IO (S.Socket S.Unix S.Stream S.Default) )
        (\server-> do
          S.close server
          Files.removeLink path
        )
        (\server-> do
          S.bind server addr
          S.listen server 1
          -- This is a nifty trick inspired by a @snoyman post: We want to catch
          -- all synchronous exceptions and restart the handler, but stop as soon
          -- as the thread receives any async exception. The only way to do it is
          -- by creating another worker thread.
          forever $ withAsync (acceptAndHandle server) $ waitCatch >=> \case
              Left e   -> LOG.warningM "Administration" $ "Connection terminated with " ++ show (e :: SomeException)
              Right () -> LOG.infoM "Administration" "Administrator disconnected."
        )
  where

    acceptAndHandle server =
      bracket (S.accept server) (S.close . fst)
        (\(sock,_)-> do
          LOG.infoM "Administration" "Administrator connected via local unix domain socket."
          receiveMessage sock >>= \case
            Nothing -> pure ()
            Just request -> do
              LOG.infoM "Administration" $ "Administrator executed command: " ++ show request
              response <- process request hum
              sendMessage sock response
        ) `catch` (\e->
          LOG.infoM "Administration" $ "Administrator disconnected with " ++ show (e :: S.SocketException) ++ "."
        )
    receiveMessage :: S.Socket S.Unix S.Stream S.Default -> IO (Maybe Request.Request)
    receiveMessage sock = execute (decoder `B.pushChunk` mempty) >>= \case
      Nothing -> pure Nothing
      Just (msg, _) -> pure (Just msg)
      where
        decoder = B.runGetIncremental B.get
        execute = \case
          B.Partial continuation -> do
            bs <- S.receive sock 4096 mempty
            if BS.null bs
              then pure Nothing -- peer closed connection
              else execute $ continuation (Just bs)
          B.Done leftover _ msg -> pure $ Just (msg, leftover)
          B.Fail _ _ failure -> do
            LOG.warningM "Administration" $ "Parser error: " ++ show failure
            pure Nothing
    sendMessage :: S.Socket S.Unix S.Stream S.Default -> Response.Response -> IO ()
    sendMessage sock msg =
      void $ S.sendAllBuilder sock 4096 (B.execPut $ B.put msg) mempty

process :: (Authenticator auth, FromJSON (AuthenticatorConfig auth), Show (AuthenticatorConfig auth)) => Request.Request -> Hummingbird auth -> IO Response.Response
process Request.Help _ =
  pure Response.Help

process Request.BrokerStatus broker =
  Response.BrokerStatus
  <$> pure (versionName $ humSettings broker)
  <*> Broker.getUptime (humBroker broker)
  <*> (IM.size <$> Broker.getSessions (humBroker broker))
  <*> (R.foldl' (\acc set-> acc + IS.size set) 0 <$> Broker.getSubscriptions (humBroker broker))
  <*> (status <$> (poll =<< readMVar (humTransport  broker)))
  <*> (status <$> (poll =<< readMVar (humTerminator broker)))
  <*> (status <$> (poll =<< readMVar (humSysInfo    broker)))
  where
    status Nothing           = Response.Running
    status (Just (Right ())) = Response.Stopped
    status (Just (Left e))   = Response.StoppedWithException (show e)

process Request.AuthStatus broker = do
  authenticator <- readMVar (humAuthenticator broker)
  e <- getLastException authenticator
  pure $ Response.AuthStatus (show <$> e)

process Request.AuthRestart broker =
  try (restartAuthenticator broker) >>= \case
    Right () -> pure (Response.Success "Done.")
    Left e   -> pure (Response.Failure $ show (e :: SomeException ))

process Request.SessionList broker = do
  sessions <- Broker.getSessions (humBroker broker)
  Response.SessionList <$> mapM sessionInfo (IM.elems sessions)

process (Request.SessionStatus sid) broker =
  Broker.lookupSession sid (humBroker broker) >>= \case
    Nothing -> pure (Response.Failure "Session not found.")
    Just s  -> Response.SessionStatus <$> sessionInfo s

process (Request.SessionDisconnect sid) broker =
  Broker.lookupSession sid (humBroker broker) >>= \case
    Nothing -> pure (Response.Failure "Session not found.")
    Just s  -> try (Session.disconnect s) >>= \case
      Right () -> pure (Response.Success "Done.")
      Left e   -> pure (Response.Failure $ show (e :: SomeException))

process (Request.SessionTerminate sid) broker =
  Broker.lookupSession sid (humBroker broker) >>= \case
    Nothing -> pure (Response.Failure "Session not found.")
    Just s  -> try (Session.terminate s) >>= \case
      Right () -> pure (Response.Success "Done.")
      Left e   -> pure (Response.Failure $ show (e :: SomeException))

process (Request.SessionSubscriptions sid) broker =
  Broker.lookupSession sid (humBroker broker) >>= \case
    Nothing -> pure (Response.Failure "Session not found.")
    Just s  -> Response.SessionSubscriptions . show <$> Session.getSubscriptions s

process Request.TransportsStatus broker =
  statusTransports broker >>= \case
    Running -> pure (Response.Success "Running.")
    Stopped -> pure (Response.Success "Stopped.")
    StoppedWithException e -> pure (Response.Failure $ "Stopped with exception: " ++ show e)

process Request.TransportsStart broker =
  try (startTransports broker) >>= \case
    Right () -> pure (Response.Success "Done.")
    Left e -> pure (Response.Failure $ show (e :: SomeException))

process Request.TransportsStop broker =
  try (stopTransports broker) >>= \case
    Right () -> pure (Response.Success "Done.")
    Left e -> pure (Response.Failure $ show (e :: SomeException))

process Request.ConfigStatus broker =
  getConfig broker >>= \config-> pure (Response.Success $ show config)

process Request.ConfigReload broker =
  reloadConfig broker >>= \case
    Right _ -> pure (Response.Success "Done.")
    Left e -> pure (Response.Failure e)

process Request.Quit _ =
  pure (Response.Success "Bye.")

sessionInfo :: Session.Session auth -> IO Response.SessionInfo
sessionInfo session = do
  connection    <- Session.getConnectionState session
  stats         <- Session.getStatistic session
  principal     <- Session.getPrincipal session
  pure Response.SessionInfo
    { Response.sessionIdentifier          = Session.identifier session
    , Response.sessionCreatedAt           = Session.createdAt session
    , Response.sessionClientIdentifier    = Session.clientIdentifier session
    , Response.sessionPrincipalIdentifier = Session.principalIdentifier session
    , Response.sessionPrincipal           = principal
    , Response.sessionConnectionState     = connection
    , Response.sessionStatistic           = stats
    }
