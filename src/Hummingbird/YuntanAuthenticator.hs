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
import qualified Crypto.BCrypt                      as BCrypt
import           Data.Aeson                         (FromJSON (..), (.:?))
import           Data.Aeson.Types
import qualified Data.Attoparsec.ByteString         as AP
import qualified Data.ByteString                    as BS
import           Data.Functor.Identity
import qualified Data.Map                           as M
import           Data.Maybe
import qualified Data.Text                          as T
import qualified Data.Text.Encoding                 as T
import           Data.Typeable
import           Data.UUID                          (UUID)
import           Data.Word

import           Network.MQTT.Broker.Authentication
import           Network.MQTT.Message
import qualified Network.MQTT.Trie                  as R

import qualified Hummingbird.Configuration          as C

data YuntanAuthenticator
   = YuntanAuthenticator
   { authPrincipals   :: M.Map UUID YuntanPrincipalConfig
   , authDefaultQuota :: Quota
   } deriving (Eq, Show)

data YuntanPrincipalConfig
   = YuntanPrincipalConfig
   { cfgUsername     :: Maybe T.Text
   , cfgPasswordHash :: Maybe BS.ByteString
   , cfgQuota        :: Maybe YuntanQuotaConfig
   , cfgPermissions  :: M.Map Filter (Identity [C.Privilege])
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
       { cfgPrincipals   :: M.Map UUID YuntanPrincipalConfig
       , cfgDefaultQuota :: Quota
       }
  data AuthenticationException YuntanAuthenticator
     = YuntanAuthenticationException deriving (Eq, Ord, Show, Typeable)

  newAuthenticator config = YuntanAuthenticator
    <$> pure (cfgPrincipals config)
    <*> pure (cfgDefaultQuota config)

  authenticate auth req =
    pure $ case requestCredentials req of
      Just (reqUser, Just reqPass) ->
        case mapMaybe (byUsernameAndPassword reqUser reqPass) $ M.assocs (authPrincipals auth) of
          [(uuid, _)] -> Just uuid
          _           -> Nothing
      _ -> Nothing
    where
      byUsernameAndPassword (Username reqUser) (Password reqPass) p@(_, principal) = do
        -- Maybe monad - yields Nothing on failure!
        user <- cfgUsername principal
        pwhash <- cfgPasswordHash principal
        -- The user is authenticated if username _and_ supplied password match.
        if user == reqUser && BCrypt.validatePassword pwhash reqPass
          then Just p
          else Nothing

  getPrincipal auth pid =
    case M.lookup pid (authPrincipals auth) of
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
    <$> v .:? "username"
    <*> ((T.encodeUtf8 <$>) <$> v .:? "password")
    <*> v .:? "quota"
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
    <$> v .: "principals"
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
