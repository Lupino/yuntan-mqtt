{-# LANGUAGE ExplicitForAll      #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}
module Hummingbird (VendorSettings (..), runWithVendorSettings) where
--------------------------------------------------------------------------------
-- |
-- Module      :  Hummingbird
-- Copyright   :  (c) Lars Petersen 2017
-- License     :  MIT
--
-- Maintainer  :  info@lars-petersen.net
-- Stability   :  experimental
--------------------------------------------------------------------------------

import           Options
import qualified Hummingbird.Internal               as HI

{-# ANN module "HLint: ignore Use newtype instead of data" #-}

data VendorSettings = VendorSettings
  { vendorVersionName :: String
  } deriving (Eq, Ord, Show)

data MainOptions = MainOptions

data BrokerOptions = BrokerOptions
  { configFilePath :: FilePath }

data VersionOptions = VersionOptions

instance Options MainOptions where
  defineOptions = pure MainOptions

instance Options BrokerOptions where
  defineOptions = BrokerOptions
    <$> simpleOption "config" "/etc/hummingbird/config.yml" "Path to the .yml config file"

instance Options VersionOptions where
  defineOptions = pure VersionOptions

runWithVendorSettings :: VendorSettings -> IO ()
runWithVendorSettings vendorSettings = runSubcommand
  [ subcommand "broker"  runBroker
  , subcommand "version" runVersion
  ]
  where

    runBroker :: MainOptions -> BrokerOptions -> [String] -> IO ()
    runBroker _ opts _ = HI.start settings
      where
        settings = HI.Settings {
          HI.versionName = vendorVersionName vendorSettings
        , HI.configFilePath = configFilePath opts
        }

    runVersion :: MainOptions -> VersionOptions -> [String] -> IO ()
    runVersion _ _ _ =
      putStrLn (vendorVersionName vendorSettings)
