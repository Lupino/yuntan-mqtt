--------------------------------------------------------------------------------
-- |
-- Module      :  Main
-- Copyright   :  (c) Lars Petersen 2017
-- License     :  MIT
--
-- Maintainer  :  info@lars-petersen.net
-- Stability   :  experimental
--------------------------------------------------------------------------------
module Main where

import           Hummingbird

main :: IO ()
main =
  runWithVendorSettings settings
  where
    settings = VendorSettings {
      vendorVersionName = "0.5.0.0"
    }
