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
import           Control.Exception                  (Exception, try)
import           Data.Aeson                         (FromJSON (..), (.:?))
import           Data.Aeson.Types
import qualified Data.Attoparsec.ByteString         as AP
import           Data.Functor.Identity
import           Data.HashMap.Strict                (HashMap)
import qualified Data.HashMap.Strict                as HM
import           Data.List                          (intercalate)
import qualified Data.Map                           as M
import           Data.Maybe
import           Data.String                        (IsString, fromString)
import qualified Data.Text                          as T
import qualified Data.Text.Encoding                 as T
import           Data.Typeable
import           Data.UUID                          (UUID, toString)
import qualified Hummingbird.Configuration          as C
import           Network.MQTT.Broker.Authentication
import           Network.MQTT.Message
import qualified Network.MQTT.Trie                  as R
import           Network.Wreq                       (getWith)
import qualified System.Log.Logger                  as Log
import           Yuntan.Base                        (Gateway (..), initGateway)
import           Yuntan.Base                        (getOptionsAndSign)
import           Yuntan.Types.Result                (ErrResult (errMsg))
import           Yuntan.Utils.Wreq                  (responseJSON)

newtype Device
  = Device
  { devUUID :: UUID
  }

data Service
  = Service
  { srvEndpoint :: Gateway
  , srvPassword :: Maybe T.Text
  , srvUUID     :: Maybe UUID
  , srvQuota    :: Maybe YuntanQuotaConfig
  } deriving (Show)

data YuntanEnv
  = YuntanEnv
  { envGateway  :: Gateway
  , envPassword :: Maybe T.Text
  , envUUID     :: Maybe UUID
  , envQuota    :: Maybe YuntanQuotaConfig
  } deriving (Show)

data YuntanAuthenticator
   = YuntanAuthenticator
   { authEnvList      :: [YuntanEnv]
   , authDefaultQuota :: Quota
   , adminPrincipal   :: YuntanPrincipalConfig
   , authUUIDMap      :: MVar (HashMap UUID String)
   }

data YuntanPrincipalConfig
   = YuntanPrincipalConfig
   { cfgQuota       :: Maybe YuntanQuotaConfig
   , cfgUsername    :: Maybe T.Text
   , cfgPassword    :: Maybe T.Text
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
       { cfgServiceList    :: [Service]
       , cfgDefaultQuota   :: Quota
       , cfgAdminPrincipal :: YuntanPrincipalConfig
       } deriving (Show)
  data AuthenticationException YuntanAuthenticator
     = YuntanAuthenticationException deriving (Eq, Ord, Show, Typeable)

  newAuthenticator config = do
    envList <- mapM (\s -> do
      gw <- initGateway $ srvEndpoint s
      pure YuntanEnv
        { envGateway = gw
        , envPassword = srvPassword s
        , envUUID     = srvUUID s
        , envQuota    = srvQuota s
        }) $ cfgServiceList config

    uuidM <- newMVar HM.empty

    return $ YuntanAuthenticator
      { authEnvList      = envList
      , authDefaultQuota = cfgDefaultQuota config
      , adminPrincipal   = cfgAdminPrincipal config
      , authUUIDMap      = uuidM
      }

  authenticate auth req =
    case requestCredentials req of
      Just (Username key, Just (Password passwd)) -> getUUID auth key $ T.decodeUtf8 passwd
      _                                           -> return Nothing

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
    <*> v .:? "password"
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

instance FromJSON Device where
  parseJSON (Object v) = Device
    <$> v .: "uuid"
  parseJSON invalid = typeMismatch "Device" invalid

instance FromJSON Service where
  parseJSON (Object v) = Service
    <$> v .: "endpoint"
    <*> v .:? "password"
    <*> v .:? "uuid"
    <*> v .:? "quota"
  parseJSON invalid = typeMismatch "Service" invalid

instance FromJSON (AuthenticatorConfig YuntanAuthenticator) where
  parseJSON (Object v) = YuntanAuthenticatorConfig
    <$> v .: "services"
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

authEnv :: YuntanAuthenticator -> String -> Maybe YuntanEnv
authEnv auth key = go $ authEnvList auth
  where go :: [YuntanEnv] -> Maybe YuntanEnv
        go [] = Nothing
        go (x:xs) | appKey (envGateway x) == key = Just x
                  | otherwise = go xs

authEnvByUUID :: YuntanAuthenticator -> UUID -> Maybe YuntanEnv
authEnvByUUID auth pid = go $ authEnvList auth
  where go :: [YuntanEnv] -> Maybe YuntanEnv
        go [] = Nothing
        go (x:xs) | envUUID x == Just pid = Just x
                  | otherwise = go xs

--   get   "/api/devices/:uuidOrToken/"
getDevice :: Gateway -> T.Text -> IO Device
getDevice gw token = do
  opts <- getOptionsAndSign "GET" path [] gw
  responseJSON $ getWith opts uri
  where path = concat [ "/api/devices/", T.unpack token, "/"]
        uri = host gw ++ path

getUUID :: YuntanAuthenticator -> T.Text -> T.Text -> IO (Maybe UUID)
getUUID auth key token =
  if cfgUsername principal == Just key then
    if cfgPassword principal == Just token then pure $ cfgUUID principal
                                           else pure Nothing
  else
    case authEnv auth (T.unpack key) of
      Nothing -> pure Nothing
      Just env ->
        if envPassword env == Just token then pure (envUUID env)
        else do
          u <- try $ getDevice (envGateway env) token
          case u of
            Left e -> Log.errorM "Hummingbird" (errMsg e) >> pure Nothing
            Right (Device u0) ->
              modifyMVarMasked (authUUIDMap auth) $ \uuidMap ->
                pure (HM.insert u0 (T.unpack key) uuidMap, Just u0)

  where principal = adminPrincipal auth

getPrincipalConfig :: YuntanAuthenticator -> UUID -> IO (Maybe YuntanPrincipalConfig)
getPrincipalConfig auth pid =
  if cfgUUID principal == Just pid then
    pure $ Just principal { cfgUsername = Nothing }
  else
    case authEnvByUUID auth pid of
      Just env0 ->
        pure $ Just YuntanPrincipalConfig
          { cfgQuota = envQuota env0
          , cfgUsername = Just (mkName [appKey (envGateway env0)])
          , cfgPassword = envPassword env0
          , cfgUUID = envUUID env0
          , cfgPermissions = srvPerm $ appKey (envGateway env0)
          }
      Nothing ->
        modifyMVarMasked (authUUIDMap auth) $ \uuidMap ->
          case HM.lookup pid uuidMap of
            Nothing -> pure (uuidMap, Nothing)
            Just key -> do
              let newMap = HM.delete pid uuidMap
              case authEnv auth key of
                Nothing -> pure (newMap, Nothing)
                Just env ->
                  pure (newMap, Just YuntanPrincipalConfig
                    { cfgQuota = envQuota env
                    , cfgUsername = Just $ mkName [key, toString pid]
                    , cfgPassword = Nothing
                    , cfgUUID = Just pid
                    , cfgPermissions = normalPerm key
                    })

  where principal = adminPrincipal auth
        perm = Identity [C.Publish, C.Subscribe, C.Retain]
        mkPerm strs = M.fromList [(mkName strs, perm)]

        normalPerm key = mkPerm [key, toString pid, "#"]
        srvPerm key = mkPerm [key, "#"]

        mkName :: IsString a => [String] -> a
        mkName strs = fromString $ "/" ++ (intercalate "/" strs)
