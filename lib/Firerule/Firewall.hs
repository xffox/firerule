{-# LANGUAGE FunctionalDependencies #-}
module Firerule.Firewall(Firewall(..)) where

import qualified Firerule.Conf as Conf

class Firewall f r | f -> r where
    create :: f -> Conf.Firewall -> IO r
    use :: f -> r -> IO ()
