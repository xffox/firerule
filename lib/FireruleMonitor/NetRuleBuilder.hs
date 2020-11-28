{-# LANGUAGE LambdaCase #-}
module FireruleMonitor.NetRuleBuilder where

import qualified Data.List as List
import qualified Data.Set as Set
import qualified Data.Maybe as Maybe
import qualified Text.Printf as Printf
import qualified System.IO as SIO
import qualified System.IO.Error as SIOError
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Monad.Trans.Class as Trans
import qualified Control.DeepSeq as DeepSeq
import qualified Control.Exception as Exception

import qualified Firerule.Format.RuleParser as RuleParser
import qualified Firerule.Format.PrefixTree as PrefixTree
import qualified Firerule.Format.ConfBuilder as ConfBuilder
import qualified Firerule.CondTree as CondTree
import qualified Firerule.Conf as Conf
import qualified Firerule.Firewall as Firewall
import qualified FireruleMonitor.NetRule as NetRule

readNetRule :: (Firewall.Firewall f r) => f ->
    String -> Except.ExceptT String IO (NetRule.NetRule (String, r))
readNetRule fh path = do
    inp <- Trans.lift $
        Exception.catch
            (SIO.withFile path SIO.ReadMode $ \h -> do
                inp <- SIO.hGetContents h
                Exception.evaluate $ DeepSeq.rnf inp
                return inp)
            (\exc -> do
                let err = show (exc :: Exception.IOException)
                fail $ Printf.printf
                      "failed to read net rule file: %s: '%s'" err path)
    buildNetRule fh inp

buildNetRule fh fr = do
    (RuleParser.Firewall rs) <- liftEither $ RuleParser.parseFirewall fr
    case rs of
      [RuleParser.Rule "network" jumps] ->
          NetRule.NetRule <$>
              fmap Maybe.catMaybes (mapM (buildJump fh) jumps)
      _ -> fail "invalid net rule: should be \"network\" only"

buildConnectionNameCondition connections = return $
    NetRule.ConnectionName (Set.fromList connections)
buildConnectionNameIncludeCondition patterns = return $
    NetRule.ConnectionNameInclude patterns
buildConnectionNameExcludeCondition patterns = return $
    NetRule.ConnectionNameExclude patterns

buildJump fh (RuleParser.Jump act tr) =
    (\fw cond -> fmap (\v -> ((act, v), cond)) fw) <$>
            tryBuildFirewall fh act <*>
                ((transformNamespaceNegation tr) >>= (mapM buildCondition))
buildJump fh (RuleParser.DefaultJump act) =
    (\fw cond -> fmap (\v -> ((act, v), cond)) fw) <$>
            tryBuildFirewall fh act <*> pure CondTree.NodeTrue

tryBuildFirewall fh path = do
    fileContent <- Trans.lift $
        Exception.catch
            (SIO.withFile path SIO.ReadMode $ \h -> do
                    inp <- SIO.hGetContents h
                    Exception.evaluate $ DeepSeq.rnf inp
                    return $ Just inp)
            (\case {
                exc | SIOError.isDoesNotExistError exc ->
                    return Nothing;
                exc -> do
                    let err = show (exc :: Exception.IOException)
                    fail $ Printf.printf
                            "failed to read firewall file: %s: '%s'" err path;
                   })
    case fileContent of
      Nothing -> return Nothing
      (Just inp) -> do
        conf <- liftEither $ RuleParser.parseFirewall inp >>=
            ConfBuilder.buildConf
        fmap Just $ Trans.lift $ Firewall.create fh conf

-- TODO: fix condition snd arguments
buildCondition (RuleParser.Condition as@((True, ns):args)) =
    case PrefixTree.findPrefix conditions ns of
      Just b -> b (map snd args)
      _ -> fail $ Printf.printf "condition not found: %s" (show as)
buildCondition _ = fail "invalid condition clause"

transformNamespaceNegation tr =
        CondTree.restructTreeM extractNamespaceNegation tr
    where extractNamespaceNegation (CondTree.Leaf (RuleParser.Condition ((False, ns):args))) =
                return $ CondTree.NodeNot $ CondTree.Leaf (RuleParser.Condition ((True, ns):args))
          extractNamespaceNegation n = return n

liftEither (Left err) = fail err
liftEither (Right val) = return val

conditions = PrefixTree.buildPrefixTree $ do
    PrefixTree.appendPrefix ["connection", "name"]
        buildConnectionNameCondition
    PrefixTree.appendPrefix ["connection", "name", "include"]
        buildConnectionNameIncludeCondition
    PrefixTree.appendPrefix ["connection", "name", "exclude"]
        buildConnectionNameExcludeCondition
