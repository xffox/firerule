module Firerule.ValueSet(SetCategory(..), ValueSet, Mergeable(..),
    category, simpleValue, fromCategory, fromValue,
    isSubset) where

data SetCategory = EmptySet | UniverseSet | SomeSet
    deriving Eq
data ValueSet a = ValueSet (Maybe a) SetCategory

category :: ValueSet a -> SetCategory
category (ValueSet _ category) = category

simpleValue :: ValueSet a -> Maybe a
simpleValue (ValueSet val _) = val

fromCategory :: Mergeable a => SetCategory -> ValueSet a
fromCategory cat@EmptySet = ValueSet emptySet cat
fromCategory cat@UniverseSet = ValueSet universeSet cat
fromCategory cat@SomeSet = ValueSet Nothing cat

fromValue :: Mergeable a => a -> ValueSet a
fromValue val = ValueSet (Just val) $
    case val of
      _ | isEmptySet val -> EmptySet
      _ | isUniverseSet val -> UniverseSet
      _ -> SomeSet

class Eq m => Mergeable m where
    intersection :: m -> m -> ValueSet m
    union :: m -> m -> ValueSet m
    emptySet :: Maybe m
    universeSet :: Maybe m
    isEmptySet :: m -> Bool
    isEmptySet = (==emptySet) . Just
    isUniverseSet :: m -> Bool
    isUniverseSet = (==universeSet) . Just

isSubset :: Mergeable m => m -> m -> Bool
isSubset a b = simpleValue (intersection a b) == Just a
