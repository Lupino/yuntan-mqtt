{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
module Hummingbird.Internal
  ( Settings (..)
  , start
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

import           Control.Concurrent.Async
import           Control.Monad                      (void)
import           Data.Default.Class
import qualified System.Log.Logger                  as Log

import qualified Network.MQTT.Broker                as Broker
import qualified Network.MQTT.Broker.Authentication as Authentication
import           Network.MQTT.Broker.Session        (Session)
import qualified Network.MQTT.Broker.Session        as Session
import           Network.MQTT.Message               (ClientPacket (..), Filter,
                                                     Message (..), QoS,
                                                     Username (..))

import           Data.String                        (IsString, fromString)
import qualified Data.Text                          as T
import           Hummingbird.Configuration
import qualified Hummingbird.Logging                as Logging
import qualified Hummingbird.Terminator             as Terminator
import qualified Hummingbird.Transport              as Transport
import           Hummingbird.YuntanAuthenticator

data Settings
  = Settings
  { versionName    :: String
  , configFilePath :: FilePath
  } deriving (Show)

-- | Create a new broker and execute the handler function in the current thread.
start :: Settings -> IO ()
start settings = do
  -- Load the config from file.
  Right config <- loadConfigFromFile (configFilePath settings) :: IO (Either String (Config YuntanAuthenticator))

  Logging.setup (logging config)

  authenticator <- Authentication.newAuthenticator (auth config)

  broker         <- Broker.newBroker (pure authenticator) brokerCallbacks

  void $ async (Transport.run broker $ transports config)

  Terminator.run broker
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
  where removeQuote :: String -> String
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
