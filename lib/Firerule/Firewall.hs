module Firerule.Firewall(Firewall(..)) where

import qualified Firerule.Conf as Conf

class Firewall f where
    apply :: f -> Conf.Firewall -> IO ()
