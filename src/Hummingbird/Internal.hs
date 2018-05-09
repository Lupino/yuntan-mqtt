{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase       #-}
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
import           Control.Monad (void)
import           Data.Default.Class
import qualified System.Log.Logger                  as Log

import qualified Network.MQTT.Broker                as Broker
import qualified Network.MQTT.Broker.Authentication as Authentication
import qualified Network.MQTT.Broker.Session        as Session

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
        Broker.onConnectionAccepted = \req session-> do
          Log.infoM "hummingbird" $
            "Connection from " ++ show (Authentication.requestRemoteAddress req) ++
            " associated with " ++ show (Session.principalIdentifier session) ++
            " and " ++ show (Session.identifier session) ++  "."

      , Broker.onConnectionRejected = \req reason-> do
          Log.warningM "hummingbird" $
            "Connection from " ++ show (Authentication.requestRemoteAddress req) ++
            " rejected: " ++ show reason ++ "."

      , Broker.onConnectionClosed = \session-> do
          Log.infoM "hummingbird" $
            "Connection associated with " ++ show (Session.identifier session) ++
            " closed by client."

      , Broker.onConnectionFailed = \session e-> do
          Log.warningM "hummingbird" $
            "Connection associated with " ++ show (Session.identifier session) ++
            " failed with exception: " ++ show e ++ "."

      , Broker.onPublishUpstream   = \_-> pure ()

      , Broker.onPublishDownstream = \_-> pure ()
      }
