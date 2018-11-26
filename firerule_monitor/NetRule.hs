module NetRule where

import qualified Data.Set as Set

import qualified Firerule.Conf as Conf
import qualified Firerule.CondTree as CT

data NetRule = NetRule Firewall [(Firewall, CT.CondTree Condition)]
type Firewall = (String, Conf.Firewall)
data Condition = ConnectionName (Set.Set String)
