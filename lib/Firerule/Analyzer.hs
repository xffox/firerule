module Firerule.Analyzer where

import qualified Data.Maybe as Maybe
import qualified Data.List as List
import qualified Data.Map.Strict as Map
import qualified Data.Ord as Ord
import Control.Applicative((<|>))

import qualified Firerule.CondTree as CondTree
import qualified Firerule.ValueSet as VS
import Control.Monad (foldM)

-- paths are variables with domains
-- $ (x \in S1) || (x \in S2) $

type Metric m = CondTree.CondTree m -> Int

simplify :: (Ord m, VS.Mergeable m) =>
    [CondTree.CondTree m -> Maybe (CondTree.CondTree m)] ->
    Metric m ->
    CondTree.CondTree m ->
    CondTree.CondTree m
simplify ops metric tr =
    let r = simplifyCands ops metric tr
    in if null r
        then tr
        else List.minimumBy (Ord.comparing metric) r

simplifyCands ops metric tr = shrinkRow metric ops
    (seenMap metric tr) tr

-- deeper levels must know of seen entities, upper shouldn't know of deeper
-- seen
shrinkRow metric ops seen tr =
    let shrinkedTrees = shrinkDepth metric ops tr
        trs = map (\t -> (t, metric t)) $ concatMap (\t ->
            Maybe.mapMaybe (`applyCommutatively` t) ops) shrinkedTrees
        seen' = Map.update (\v -> if fst v == tr then Nothing else Just v)
            (treeKey tr) $ insert metric seen trs
        trs'' = map (\t -> (t, metric t)) $
            concatMap (shrinkDepth metric ops . fst) seen'
        seen'' = insert metric seen' [(tr, metric tr)]
        seen''' = insert metric seen'' $
            map (\t -> (t, metric t)) shrinkedTrees
        seen'''' = insert metric seen''' trs''
     in map fst $ Map.elems seen''''

applyCommutatively op n@(CondTree.NodeAnd left right) =
    op n <|> op (CondTree.NodeAnd right left)
applyCommutatively op n@(CondTree.NodeOr left right) =
    op n <|> op (CondTree.NodeOr right left)
applyCommutatively op n = op n

shrinkDepth metric ops (CondTree.NodeOr left right) =
    let trLeft = shrinkRow metric ops (seenMap metric left) left
        trRight = shrinkRow metric ops (seenMap metric right) right
    in [CondTree.NodeOr a b | a <- trLeft, b <- trRight]
shrinkDepth metric ops (CondTree.NodeAnd left right) =
    let trLeft = shrinkRow metric ops (seenMap metric left) left
        trRight = shrinkRow metric ops (seenMap metric right) right
    in [CondTree.NodeAnd a b | a <- trLeft, b <- trRight]
shrinkDepth metric ops (CondTree.NodeNot node) =
    let trs = shrinkRow metric ops (seenMap metric node) node
    in fmap CondTree.NodeNot trs
shrinkDepth _ _ _ = []

insert metric = List.foldl' insert'
   where insert' seen c@(cur, curMetric) =
           let key = treeKey cur
            in case Map.lookup key seen of
                 (Just (_, storedMetric)) ->
                     if curMetric < storedMetric
                        then Map.insert key c seen
                        else seen
                 Nothing -> Map.insert key c seen

treeKey = CondTree.CutCondTree 2

seenMap metric tr = Map.singleton (treeKey tr) (tr, metric tr)
