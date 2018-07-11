module Main where

import qualified System.Posix.Signals as Signals
import qualified Text.Printf as Printf
import qualified Options.Applicative as Opt
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Concurrent.MVar as MVar
import Control.Applicative((<**>))
import Data.Semigroup((<>))

import qualified NetRuleBuilder as NetRuleBuilder
import qualified NetRuleExecutor as NetRuleExecutor

data Config = Config {
        path :: String
    }

configParse = Config <$>
    Opt.strOption (
            Opt.long "path" <>
            Opt.short 'p' <>
            Opt.metavar "PATH"
        )

main = do
    config <- Opt.execParser $
        Opt.info (configParse <**> Opt.helper) Opt.fullDesc
    res <- Except.runExceptT $ NetRuleBuilder.readNetRule $ path config
    case res of
      Left err -> fail err
      Right nr -> startMonitor nr

startMonitor nr = do
    cont <- MVar.newEmptyMVar
    handle <- NetRuleExecutor.runNetRule nr
    Signals.installHandler Signals.sigINT
      (Signals.Catch $ stopMonitor (cont, handle))
      (Just $ Signals.addSignal Signals.sigTERM Signals.emptySignalSet)
    MVar.takeMVar cont

stopMonitor (cont, handle) = do
    NetRuleExecutor.stopNetRule handle
    MVar.putMVar cont 0
