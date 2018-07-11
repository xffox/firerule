module Firerule.ValueSet where

-- TODO: join is union, should return list - more consistent
class Eq m => Mergeable m where
    mergeIntersect :: m -> m -> [m]
    mergeJoin :: m -> m -> Maybe m
