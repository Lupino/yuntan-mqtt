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

import           Control.Concurrent.MVar
import           Control.Exception                  (Exception)
import           Data.Aeson                         (FromJSON (..), (.:?))
import           Data.Aeson.Types
import qualified Data.Attoparsec.ByteString         as AP
import           Data.Functor.Identity
import           Data.HashMap.Strict                (HashMap)
import qualified Data.HashMap.Strict                as HM
import qualified Data.Map                           as M
import           Data.Maybe
import           Data.String                        (fromString)
import qualified Data.Text                          as T
import qualified Data.Text.Encoding                 as T
import           Data.Typeable
import           Data.UUID                          (UUID, fromText, toString,
                                                     toText)

import           Network.MQTT.Broker.Authentication
import           Network.MQTT.Message
import qualified Network.MQTT.Trie                  as R

import qualified Hummingbird.Configuration          as C

import           Haxl.Core                          (GenHaxl, StateStore,
                                                     initEnv, runHaxl,
                                                     stateEmpty, stateSet, try)

import           Yuntan.API.User                    (getBind, initUserState)
import           Yuntan.Base                        (AppEnv, Gateway (..),
                                                     gateway, initGateway)
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
   , adminPrincipal   :: YuntanPrincipalConfig
   , authUUIDMap      :: MVar (HashMap UUID String)
   }

data YuntanPrincipalConfig
   = YuntanPrincipalConfig
   { cfgQuota       :: Maybe YuntanQuotaConfig
   , cfgUsername    :: Maybe T.Text
   , cfgUUID        :: Maybe UUID
   , cfgPermissions :: M.Map Filter (Identity [C.Privilege])
   } deriving (Eq, Show)

data YuntanQuotaConfig
   = YuntanQuotaConfig
   { cfgQuotaMaxSessions          :: Maybe Int
   , cfgQuotaMaxIdleSessionTTL    :: Maybe Int
   , cfgQuotaMaxPacketSize        :: Maybe Int
   , cfgQuotaMaxPacketIdentifiers :: Maybe Int
   , cfgQuotaMaxQueueSizeQoS0     :: Maybe Int
   , cfgQuotaMaxQueueSizeQoS1     :: Maybe Int
   , cfgQuotaMaxQueueSizeQoS2     :: Maybe Int
   } deriving (Eq, Ord, Show)

instance Authenticator YuntanAuthenticator where
  data AuthenticatorConfig YuntanAuthenticator
     = YuntanAuthenticatorConfig
       { cfgService        :: Gateway
       , cfgDefaultQuota   :: Quota
       , cfgAdminPrincipal :: YuntanPrincipalConfig
       } deriving (Show)
  data AuthenticationException YuntanAuthenticator
     = YuntanAuthenticationException deriving (Eq, Ord, Show, Typeable)

  newAuthenticator config = do
    userC <- initGateway $ cfgService config

    uuidM <- newMVar HM.empty

    return $ YuntanAuthenticator
      { authStateStore   = stateSet (initUserState . numThreads $ cfgService config) stateEmpty
      , authEnv          = YuntanEnv userC
      , authDefaultQuota = cfgDefaultQuota config
      , adminPrincipal   = cfgAdminPrincipal config
      , authUUIDMap      = uuidM
      }

  authenticate auth req =
    case requestCredentials req of
      Nothing                     -> return Nothing
      Just (Username reqToken, _) -> getUUID auth reqToken

  getPrincipal auth pid = do
    config <- getPrincipalConfig auth pid
    case config of
      Nothing -> pure Nothing
      Just pc -> pure $ Just Principal {
          principalUsername             = Username <$> cfgUsername pc
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
          quotaMaxSessions          = fromMaybe (quotaMaxSessions          defaultQuota) (cfgQuotaMaxSessions          quota)
        , quotaMaxIdleSessionTTL    = fromMaybe (quotaMaxIdleSessionTTL    defaultQuota) (cfgQuotaMaxIdleSessionTTL    quota)
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
    <*> v .:? "username"
    <*> v .:? "uuid"
    <*> v .:? "permissions" .!= mempty
  parseJSON invalid = typeMismatch "YuntanPrincipalConfig" invalid

instance FromJSON YuntanQuotaConfig where
  parseJSON (Object v) = YuntanQuotaConfig
    <$> v .:? "maxSessions"
    <*> v .:? "maxIdleSessionTTL"
    <*> v .:? "maxPacketSize"
    <*> v .:? "maxPacketIdentifiers"
    <*> v .:? "maxQueueSizeQoS0"
    <*> v .:? "maxQueueSizeQoS1"
    <*> v .:? "maxQueueSizeQoS2"
  parseJSON invalid = typeMismatch "YuntanQuotaConfig" invalid

instance FromJSON Quota where
  parseJSON (Object v) = Quota
    <$> v .: "maxSessions"
    <*> v .: "maxIdleSessionTTL"
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
    <*> v .: "admin_principal"
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
runIO (YuntanAuthenticator state env _ _ _) m = do
  env0 <- initEnv state env
  runHaxl env0 m

getUUID :: YuntanAuthenticator -> T.Text -> IO (Maybe UUID)
getUUID auth token = do
  if cfgUsername principal == Just token then pure $ cfgUUID principal
  else do
    u <- runIO auth $ try $ getBind token
    case u of
      Left e   -> Log.errorM "Hummingbird" (errMsg e) >> return Nothing
      Right Bind {getBindExtra = extra} ->
        case extra ^? Lens.key "uuid" . Lens._String of
          Nothing   -> return Nothing
          Just uuid ->
            case fromText uuid of
              Nothing -> return Nothing
              Just u0 -> modifyMVarMasked (authUUIDMap auth) $ \uuidMap -> do
                pure $ (HM.insert u0 (T.unpack $ T.takeWhile (/=':') token) uuidMap, Just u0)

  where principal = adminPrincipal auth

getPrincipalConfig :: YuntanAuthenticator -> UUID -> IO (Maybe YuntanPrincipalConfig)
getPrincipalConfig auth pid = do
  if cfgUUID principal == Just pid then pure $ Just principal { cfgUsername = Nothing }
  else do
    u <- runIO auth $ try $ getBind $ toText pid
    case u of
      Left e                            -> Log.errorM "Hummingbird" (errMsg e) >> return Nothing
      Right Bind {getBindExtra = extra} ->
        case fromJSON extra of
          Error _   -> return Nothing
          Success a ->
            modifyMVarMasked (authUUIDMap auth) $ \uuidMap -> do
              case HM.lookup pid uuidMap of
                Nothing -> pure (uuidMap, Nothing)
                Just key -> pure $ (HM.delete pid uuidMap, Just a {cfgUsername = Just (fromString $ "/" ++ key ++ "/" ++ toString pid)})

  where principal = adminPrincipal auth
