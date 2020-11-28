module FireruleMonitor.NetRule where

import qualified Data.Set as Set
import qualified Data.Map as Map

import qualified Firerule.Conf as Conf
import qualified Firerule.CondTree as CT
import qualified Firerule.BoolPair as BoolPair
import qualified FireruleMonitor.NetInfo as NetInfo
import qualified FireruleMonitor.PatternMatcher as PatternMatcher

type Target = String
newtype NetRule a = NetRule [(a, CT.CondTree Condition)]
data Condition = ConnectionName (Set.Set String)
               | ConnectionNameInclude [String]
               | ConnectionNameExclude [String]

newtype Selector a = Selector [(a, [Match])]

makeSelector :: NetRule a -> Selector a
makeSelector (NetRule conds) =
    Selector $
        map (\(target, tree) -> (target, processTree tree)) conds

selectNetRule :: Selector a -> NetInfo.NetInfo -> Maybe a
selectNetRule (Selector matches) info =
    case map fst $
        filter (any (checkMatch info) . snd) matches of
        [] -> Nothing
        (v:vs) -> Just v

data MatchSet =
    MatchSet (Set.Set (BoolPair.BoolPair String))
        (Set.Set (BoolPair.BoolPair String))

data Match = Match MatchSet (Maybe Bool)

checkMatch :: NetInfo.NetInfo -> Match -> Bool
checkMatch _ (Match _ (Just True)) = True
checkMatch _ (Match _ (Just False)) = False
checkMatch info (Match (MatchSet includes excludes) _) =
    let names = NetInfo.networks info
        excludedNames = matchNames excludes names
        includedNames = matchNames includes names
     in all (\pat -> any (pat `PatternMatcher.match`) names) (
         map snd (Set.toList includes)) &&
             Set.fromList names == Set.union includedNames excludedNames
    where matchNames patterns ns = Set.fromList $
            filter (\name -> any (`PatternMatcher.match` name) $
                map snd $ Set.toList patterns) ns

processTree :: CT.CondTree Condition -> [Match]
-- ConnectionName is deprecated
processTree (CT.Leaf (ConnectionName names)) =
    [Match (MatchSet
        Set.empty (Set.map (\v -> (True, v)) names)) Nothing]
processTree (CT.Leaf (ConnectionNameInclude patterns)) =
    [Match (MatchSet
        (Set.fromList $ map (\v -> (True, v)) patterns) Set.empty) Nothing]
processTree (CT.Leaf (ConnectionNameExclude patterns)) =
    [Match (MatchSet
        Set.empty (Set.fromList $ map (\v -> (True, v)) patterns)) Nothing]
processTree (CT.NodeOr left right) =
    processTree left ++ processTree right
processTree (CT.NodeAnd left right) =
    let leftMatches = processTree left
        rightMatches = processTree right
     in [joinMatches l r | l <- leftMatches , r <- rightMatches]
processTree (CT.NodeNot node) =
    undefined
processTree CT.NodeFalse =
    [Match emptyMatchSet (Just False)]
processTree CT.NodeTrue =
    [Match emptyMatchSet (Just True)]

emptyMatchSet = MatchSet Set.empty Set.empty

joinMatchSets (MatchSet include1 exclude1) (MatchSet include2 exclude2) =
    MatchSet (Set.union include1 include2) (Set.union exclude1 exclude2)

joinTruthness Nothing right = right
joinTruthness left Nothing = left
joinTruthness (Just left) (Just right) = Just (left && right)

joinMatches (Match networkNames1 truthness1) (Match networkNames2 truthness2) =
    Match (joinMatchSets networkNames1 networkNames2)
        (joinTruthness truthness1 truthness2)
