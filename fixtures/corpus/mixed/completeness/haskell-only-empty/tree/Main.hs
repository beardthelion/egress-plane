{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString.Char8 as B8
import Network.HTTP.Simple (getResponseBody, httpBS)

main :: IO ()
main = do
    response <- httpBS "https://api.example.com/haskell"
    B8.putStrLn (getResponseBody response)
