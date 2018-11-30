{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Hummingbird.Internal
  ( Hummingbird (..)
  , Settings (..)
  , new
  , start

  , getConfig
  , reloadConfig
  , startTransports
  , stopTransports
  , restartAuthenticator
  , statusTransports
  , Status (..)
  ) where
--------------------------------------------------------------------------------
-- |
-- Module      :  Hummingbird.Internal
-- Copyright   :  (c) Lars Petersen 2017
-- License     :  MIT
--
-- Maintainer  :  info@lars-petersen.net
-- Stability   :  experimental
--------------------------------------------------------------------------------

import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad                      (void, (>=>))
import           Data.Default.Class
import qualified System.Log.Logger                  as Log

import qualified Network.MQTT.Broker                as Broker
import           Network.MQTT.Broker.Authentication (Authenticator,
                                                     AuthenticatorConfig)
import qualified Network.MQTT.Broker.Authentication as Authentication
import           Network.MQTT.Broker.Session        (Session)
import qualified Network.MQTT.Broker.Session        as Session
import           Network.MQTT.Message               (ClientPacket (..), Filter,
                                                     Message (..), QoS,
                                                     Username (..))

import           Data.Aeson
import           Data.String                        (IsString, fromString)
import qualified Data.Text                          as T
import           Hummingbird.Configuration
import qualified Hummingbird.Logging                as Logging
import qualified Hummingbird.SysInfo                as SysInfo
import qualified Hummingbird.Terminator             as Terminator
import qualified Hummingbird.Transport              as Transport
import           System.Exit
import           System.IO

data Hummingbird auth
   = Hummingbird
   { humSettings      :: Settings auth
   , humBroker        :: Broker.Broker auth
   , humConfig        :: MVar (Config auth)
   , humAuthenticator :: MVar auth
   , humTransport     :: MVar (Async ())
   , humTerminator    :: MVar (Async ()) -- ^ Session termination thread
   , humSysInfo       :: MVar (Async ()) -- ^ Sys info publishing thread
   }

-- | The status of a worker thread.
data Status
  = Running
  | Stopped
  | StoppedWithException SomeException
  deriving (Show)

data Settings auth
  = Settings
  { versionName    :: String
  , configFilePath :: FilePath
  } deriving (Show)

new :: (Authenticator auth, FromJSON (AuthenticatorConfig auth)) => Settings auth -> IO (Hummingbird auth)
new settings = do
  -- Load the config from file.
  config <- loadConfigFromFile (configFilePath settings) >>= \case
      Left e       -> hPutStrLn stderr e >> exitFailure
      Right config -> pure config

  Logging.setup (logging config)

  mconfig        <- newMVar config
  mauthenticator <- newMVar =<< Authentication.newAuthenticator (auth config)

  broker         <- Broker.newBroker (readMVar mauthenticator) brokerCallbacks

  mterminator    <- newMVar =<< async (Terminator.run broker)
  mtransports    <- newMVar =<< async (Transport.run broker $ transports config)
  msysinfo       <- newMVar =<< async (SysInfo.run broker)

  pure Hummingbird
    { humSettings      = settings
    , humBroker        = broker
    , humConfig        = mconfig
    , humAuthenticator = mauthenticator
    , humTransport     = mtransports
    , humTerminator    = mterminator
    , humSysInfo       = msysinfo
    }

  where
    brokerCallbacks = def {
        Broker.onConnectionAccepted = \req session->
          Log.infoM "hummingbird" $
            "Connection from " ++ show (Authentication.requestRemoteAddress req) ++
            " associated with " ++ show (Session.principalIdentifier session) ++
            " and " ++ show (Session.identifier session) ++  "."

      , Broker.onConnectionRejected = \req reason->
          Log.warningM "hummingbird" $
            "Connection from " ++ show (Authentication.requestRemoteAddress req) ++
            " rejected: " ++ show reason ++ "."

      , Broker.onConnectionClosed = \session->
          Log.infoM "hummingbird" $
            "Connection associated with " ++ show (Session.identifier session) ++
            " closed by client."

      , Broker.onConnectionFailed = \session e->
          Log.warningM "hummingbird" $
            "Connection associated with " ++ show (Session.identifier session) ++
            " failed with exception: " ++ show e ++ "."

      , Broker.onPublishUpstream   = \_-> pure ()

      , Broker.onPublishDownstream = \_-> pure ()
      , Broker.preprocessPacket = preprocessPacket
      , Broker.preprocessMessage = preprocessMessage
      }

preprocessPacket :: Session auth -> ClientPacket -> IO ClientPacket
preprocessPacket session (ClientPublish pid dup message) = ClientPublish pid dup <$> fixedPacketMessage session message
preprocessPacket session (ClientSubscribe pid filters) = ClientSubscribe pid <$> fixedPacketSubscribe session filters
preprocessPacket session (ClientUnsubscribe pid filters) = ClientUnsubscribe pid <$> fixedPacketUnsubscribe session filters
preprocessPacket _ p = pure p

fixedPacketMessage :: Session auth -> Message -> IO Message
fixedPacketMessage session message = do
  principal <- Session.getPrincipal session
  pure message { msgTopic = fixedTopic (Authentication.principalUsername principal) (msgTopic message) }

fixedTopic :: (IsString a, Show a) => Maybe Username -> a -> a
fixedTopic Nothing = id
fixedTopic (Just (Username n)) = fromString . updateString (T.unpack n) . removeQuote . show

removeQuote :: String -> String
removeQuote ('"' : xs) = take (length xs - 1) xs
removeQuote xs         = xs

updateString :: String -> String -> String
updateString [] s0      = s0
updateString s []       = s
updateString s ('/':xs) = updateString s xs
updateString s xs | last s == '/' = s ++ xs
                  | otherwise = s ++ ('/':xs)

fixedPacketSubscribe :: Session auth -> [(Filter, QoS)] -> IO [(Filter, QoS)]
fixedPacketSubscribe session filters = do
  principal <- Session.getPrincipal session
  pure $ map (\(f, q) -> (fixedTopic (Authentication.principalUsername principal) f, q)) filters

fixedPacketUnsubscribe :: Session auth -> [Filter] -> IO [Filter]
fixedPacketUnsubscribe session filters = do
  principal <- Session.getPrincipal session
  pure $ map (fixedTopic (Authentication.principalUsername principal)) filters

preprocessMessage :: Session auth -> Message -> IO Message
preprocessMessage session msg = do
  principal <- Session.getPrincipal session
  case Authentication.principalUsername principal of
    Nothing -> pure msg
    Just (Username n) ->
      pure msg
        { msgTopic = fromString . drop (T.length n) . removeQuote . show $ msgTopic msg
        }

start :: Authenticator auth => Hummingbird auth -> IO ()
start hum = do
  startTransports hum
  startTerminator hum

stop  :: Hummingbird auth -> IO ()
stop hum = do
  stopTransports hum
  stopTerminator hum

startTerminator :: Hummingbird auth -> IO ()
startTerminator hum =
  startThread (humTerminator hum) (Terminator.run $ humBroker hum)

stopTerminator :: Hummingbird auth -> IO ()
stopTerminator hum = stopThread (humTerminator hum)

startSysInfo :: Hummingbird auth -> IO ()
startSysInfo hum =
  startThread (humSysInfo hum) (SysInfo.run $ humBroker hum)

stopSysInfo :: Hummingbird auth -> IO ()
stopSysInfo hum =
  stopThread (humSysInfo hum)

getConfig :: Hummingbird auth -> IO (Config auth)
getConfig hum =
  readMVar (humConfig hum)

reloadConfig :: (FromJSON (AuthenticatorConfig auth)) => Hummingbird auth -> IO (Either String (Config auth))
reloadConfig hum =
  modifyMVar (humConfig hum) $ \config->
    loadConfigFromFile (configFilePath $ humSettings hum) >>= \case
      Left  e -> pure (config, Left e)
      Right config' -> pure (config', Right config')

restartAuthenticator :: Authenticator auth => Hummingbird auth -> IO ()
restartAuthenticator hum = do
  config <- readMVar (humConfig hum)
  authenticator <- Authentication.newAuthenticator (auth config)
  void $ swapMVar (humAuthenticator hum) authenticator

startTransports :: Authenticator auth => Hummingbird auth -> IO ()
startTransports hum =
  modifyMVar_ (humTransport hum) $ \asnc->
    poll asnc >>= \case
      -- Is already running. Leave as is.
      Nothing -> pure asnc
      Just _  -> do
        config <- readMVar (humConfig hum)
        async $ Transport.run (humBroker hum) (transports config)

stopTransports :: Hummingbird auth -> IO ()
stopTransports hum =
  stopThread (humTransport hum)

statusTransports :: Hummingbird auth -> IO Status
statusTransports hum =
  withMVar (humTransport hum) $ poll >=> \case
    Nothing -> pure Running
    Just x  -> case x of
      Right () -> pure Stopped
      Left  e  -> pure (StoppedWithException e)

stopThread :: MVar (Async ()) -> IO ()
stopThread m =
  withMVar m cancel

startThread :: MVar (Async ()) -> IO () -> IO ()
startThread m t =
  modifyMVar_ m $ \asnc-> poll asnc >>= \case
    -- Is already running. Leave as is.
    Nothing -> pure asnc
    -- Is not running (anymore). Start!
    Just _  -> async t
