module Firerule.Analyzer where

import qualified Data.Maybe as Maybe
import qualified Data.List as List
import qualified Data.Ord as Ord

import qualified Firerule.CondTree as CondTree
import qualified Firerule.ValueSet as VS
import Control.Monad (foldM)

-- paths are variables with domains
-- $ (x \in S1) || (x \in S2) $

simplify :: (Eq m, VS.Mergeable m) =>
    [CondTree.CondTree m -> Maybe (CondTree.CondTree m)] ->
    (CondTree.CondTree m -> CondTree.CondTree m -> Ord.Ordering) ->
    CondTree.CondTree m ->
    CondTree.CondTree m
simplify ops metric tr =
    let r = simplifyCands ops metric tr
    in if null r
        then tr
        else List.minimumBy metric r

simplifyCands ops metric tr = shrinkRow metric ops [tr] tr

-- deeper levels must know of seen entities, upper shouldn't know of deeper
-- seen
shrinkRow metric ops seen tr =
    let trs = concatMap (\t -> Maybe.mapMaybe ($ t) ops) $
            concatMap (shrinkDepth metric ops) [tr]
        (seen', _) = insert metric seen [] trs
        trs'' = concatMap (shrinkDepth metric ops) seen'
        (seen'', _) = insert metric seen' [] trs''
     in seen''

step metric ops (s, ts) t =
    let trs = shrinkRow metric ops s t
    in insert metric s ts trs

shrinkDepth metric ops (CondTree.NodeOr left right) =
    let trLeft = shrinkRow metric ops [left] left
        trRight = shrinkRow metric ops [right] right
    in [CondTree.NodeOr left b | b <- trRight] ++
        [CondTree.NodeOr a right | a <- trLeft] ++
            [CondTree.NodeOr a b | a <- trLeft, b <- trRight]
shrinkDepth metric ops (CondTree.NodeAnd left right) =
    let trLeft = shrinkRow metric ops [left] left
        trRight = shrinkRow metric ops [right] right
    in [CondTree.NodeAnd left b | b <- trRight] ++
        [CondTree.NodeAnd a right | a <- trLeft] ++
            [CondTree.NodeAnd a b | a <- trLeft, b <- trRight]
shrinkDepth metric ops (CondTree.NodeNot node) =
    let trs = shrinkRow metric ops [node] node
    in fmap CondTree.NodeNot trs
shrinkDepth _ _ _ = []

insert metric seen r [] = (seen, r)
insert metric seen r (tr:trs) =
    let (s', r') = insert' [] seen
    in insert metric s' r' trs
        where insert' s' [] = (tr:s', tr:r)
              insert' s' (v:vs)
                    | CondTree.eqToDepth 2 tr v =
                        let mv = if metric tr v == LT then tr else v
                        in (mv:s' ++ vs, r)
                    | otherwise = insert' (v:s') vs
