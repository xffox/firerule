module FireruleMonitor.PatternMatcher(Pattern, match) where

import qualified Data.Maybe as Maybe
import qualified Text.Regex as Regex

type Pattern = String

match :: Pattern -> String -> Bool
match pat target =
    let re = Regex.mkRegex pat
     in case Regex.matchRegexAll re target of
          Nothing -> False
          (Just (_, m, _, _)) -> m == target
