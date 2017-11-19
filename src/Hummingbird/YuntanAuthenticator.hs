{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Hummingbird.YuntanAuthenticator where
--------------------------------------------------------------------------------
-- |
-- Module      :  Hummingbird.YuntanAuthenticator
-- Copyright   :  (c) Li Meng Jun 2017
-- License     :  MIT
--
-- Maintainer  :  lmjubuntu@gmail.com
-- Stability   :  experimental
--------------------------------------------------------------------------------

import           Control.Exception
import           Data.Aeson                         (FromJSON (..), (.:?))
import           Data.Aeson.Types
import qualified Data.Attoparsec.ByteString         as AP
import           Data.Functor.Identity
import qualified Data.Map                           as M
import           Data.Maybe
import qualified Data.Text                          as T
import qualified Data.Text.Encoding                 as T
import           Data.Typeable
import           Data.UUID                          (UUID, fromText, toText)
import           Data.Word

import           Network.MQTT.Broker.Authentication
import           Network.MQTT.Message
import qualified Network.MQTT.Trie                  as R

import qualified Hummingbird.Configuration          as C

import           Haxl.Core                          (GenHaxl, StateStore,
                                                     initEnv, runHaxl,
                                                     stateEmpty, stateSet)

import           Yuntan.API.User                    (getBind, initUserState)
import           Yuntan.Base                        (AppEnv, Gateway (..),
                                                     gateway, initMgr)
import           Yuntan.Types.Result                (ErrResult (errMsg))
import           Yuntan.Types.User                  (Bind (..))

import           Control.Lens                       ((^?))
import qualified Data.Aeson.Lens                    as Lens (key, _String)
import qualified System.Log.Logger                  as Log

newtype YuntanEnv
  = YuntanEnv
  { userService :: Gateway }

instance AppEnv YuntanEnv where
  gateway env "UserDataSource" = userService env
  gateway _ n                  = error $ "Unsupport data source" ++ n

data YuntanAuthenticator
   = YuntanAuthenticator
   { authStateStore   :: StateStore
   , authEnv          :: YuntanEnv
   , authDefaultQuota :: Quota
   }

data YuntanPrincipalConfig
   = YuntanPrincipalConfig
   { cfgQuota       :: Maybe YuntanQuotaConfig
   , cfgPermissions :: M.Map Filter (Identity [C.Privilege])
   } deriving (Eq, Show)

data YuntanQuotaConfig
   = YuntanQuotaConfig
   { cfgQuotaMaxIdleSessionTTL    :: Maybe Word64
   , cfgQuotaMaxPacketSize        :: Maybe Word64
   , cfgQuotaMaxPacketIdentifiers :: Maybe Word64
   , cfgQuotaMaxQueueSizeQoS0     :: Maybe Word64
   , cfgQuotaMaxQueueSizeQoS1     :: Maybe Word64
   , cfgQuotaMaxQueueSizeQoS2     :: Maybe Word64
   } deriving (Eq, Ord, Show)

instance Authenticator YuntanAuthenticator where
  data AuthenticatorConfig YuntanAuthenticator
     = YuntanAuthenticatorConfig
       { cfgService      :: Gateway
       , cfgDefaultQuota :: Quota
       }
  data AuthenticationException YuntanAuthenticator
     = YuntanAuthenticationException deriving (Eq, Ord, Show, Typeable)

  newAuthenticator config = do
    userC <- initMgr $ cfgService config
    let state = stateSet (initUserState . getGWNumThreads $ cfgService config)
              stateEmpty

    return $ YuntanAuthenticator state (YuntanEnv userC) (cfgDefaultQuota config)

  authenticate auth req =
    case requestCredentials req of
      Nothing                     -> return Nothing
      Just (Username reqToken, _) -> getUUID auth reqToken

  getPrincipal auth pid = do
    config <- getPrincipalConfig auth $ toText pid
    case config of
      Nothing -> pure Nothing
      Just pc -> pure $ Just Principal {
          principalUsername             = Nothing
        , principalQuota                = mergeQuota (cfgQuota pc) (authDefaultQuota auth)
        , principalPublishPermissions   = R.mapMaybe f $ M.foldrWithKey' R.insert R.empty (cfgPermissions pc)
        , principalSubscribePermissions = R.mapMaybe g $ M.foldrWithKey' R.insert R.empty (cfgPermissions pc)
        , principalRetainPermissions    = R.mapMaybe h $ M.foldrWithKey' R.insert R.empty (cfgPermissions pc)
        }
    where
      f (Identity xs)
        | C.Publish `elem` xs   = Just ()
        | otherwise             = Nothing
      g (Identity xs)
        | C.Subscribe `elem` xs = Just ()
        | otherwise             = Nothing
      h (Identity xs)
        | C.Retain    `elem` xs = Just ()
        | otherwise             = Nothing
      -- Prefers a user quota property over the default quota property.
      mergeQuota Nothing defaultQuota = defaultQuota
      mergeQuota (Just quota) defaultQuota = Quota {
          quotaMaxIdleSessionTTL    = fromMaybe (quotaMaxIdleSessionTTL    defaultQuota) (cfgQuotaMaxIdleSessionTTL    quota)
        , quotaMaxPacketSize        = fromMaybe (quotaMaxPacketSize        defaultQuota) (cfgQuotaMaxPacketSize        quota)
        , quotaMaxPacketIdentifiers = fromMaybe (quotaMaxPacketIdentifiers defaultQuota) (cfgQuotaMaxPacketIdentifiers quota)
        , quotaMaxQueueSizeQoS0     = fromMaybe (quotaMaxQueueSizeQoS0     defaultQuota) (cfgQuotaMaxQueueSizeQoS0     quota)
        , quotaMaxQueueSizeQoS1     = fromMaybe (quotaMaxQueueSizeQoS1     defaultQuota) (cfgQuotaMaxQueueSizeQoS1     quota)
        , quotaMaxQueueSizeQoS2     = fromMaybe (quotaMaxQueueSizeQoS2     defaultQuota) (cfgQuotaMaxQueueSizeQoS2     quota)
       }

  getLastException _ = pure Nothing

instance Exception (AuthenticationException YuntanAuthenticator)

instance FromJSON YuntanPrincipalConfig where
  parseJSON (Object v) = YuntanPrincipalConfig
    <$> v .:? "quota"
    <*> v .:? "permissions" .!= mempty
  parseJSON invalid = typeMismatch "YuntanPrincipalConfig" invalid

instance FromJSON YuntanQuotaConfig where
  parseJSON (Object v) = YuntanQuotaConfig
    <$> v .:? "maxIdleSessionTTL"
    <*> v .:? "maxPacketSize"
    <*> v .:? "maxPacketIdentifiers"
    <*> v .:? "maxQueueSizeQoS0"
    <*> v .:? "maxQueueSizeQoS1"
    <*> v .:? "maxQueueSizeQoS2"
  parseJSON invalid = typeMismatch "YuntanQuotaConfig" invalid

instance FromJSON Quota where
  parseJSON (Object v) = Quota
    <$> v .: "maxIdleSessionTTL"
    <*> v .: "maxPacketSize"
    <*> v .: "maxPacketIdentifiers"
    <*> v .: "maxQueueSizeQoS0"
    <*> v .: "maxQueueSizeQoS1"
    <*> v .: "maxQueueSizeQoS2"
  parseJSON invalid = typeMismatch "Quota" invalid

instance FromJSON (AuthenticatorConfig YuntanAuthenticator) where
  parseJSON (Object v) = YuntanAuthenticatorConfig
    <$> v .: "service"
    <*> v .: "defaultQuota"
  parseJSON invalid = typeMismatch "YuntanAuthenticatorConfig" invalid

instance FromJSON Filter where
  parseJSON (String t) =
    case AP.parseOnly filterParser (T.encodeUtf8 t) of
      Left e  -> fail e
      Right x -> pure x
  parseJSON invalid = typeMismatch "Filter" invalid

instance FromJSONKey Filter where
  fromJSONKey = FromJSONKeyTextParser $ \t->
    case AP.parseOnly filterParser (T.encodeUtf8 t) of
      Left e  -> fail e
      Right x -> pure x

runIO :: YuntanAuthenticator -> GenHaxl YuntanEnv a -> IO a
runIO (YuntanAuthenticator state env _) m = do
  env0 <- initEnv state env
  runHaxl env0 m

getUUID :: YuntanAuthenticator -> T.Text -> IO (Maybe UUID)
getUUID auth token = do
  u <- runIO auth $ getBind token
  case u of
    Left e   -> Log.errorM "Hummingbird" (errMsg e) >> return Nothing
    Right Bind {getBindExtra = extra} ->
      case extra ^? Lens.key "uuid" . Lens._String of
        Nothing   -> return Nothing
        Just uuid -> return $ fromText uuid

getPrincipalConfig :: YuntanAuthenticator -> T.Text -> IO (Maybe YuntanPrincipalConfig)
getPrincipalConfig auth pid = do
  u <- runIO auth $ getBind pid
  case u of
    Left e                            -> Log.errorM "Hummingbird" (errMsg e) >> return Nothing
    Right Bind {getBindExtra = extra} ->
      case fromJSON extra of
        Success a -> return $ Just a
        Error _   -> return Nothing
