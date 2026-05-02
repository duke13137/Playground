{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE GHC2024        #-}
module Main
  ( main
  ) where

import Network.Wai.Handler.Warp qualified as Wai
import Rapid

import App
import Database

-- $> main
main :: IO ()
main = do
  bracket acquirePool releasePool \pool ->
    rapid 0 \r -> restart r "server" $
      Wai.run 8080 (app pool)
