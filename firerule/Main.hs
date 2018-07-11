module Main where

import qualified System.IO as SIO
import qualified Text.Printf as Printf
import qualified Options.Applicative as Opt
import Control.Applicative((<**>))
import Data.Semigroup((<>))

import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.Iptables as Iptables
import qualified Firerule.Format.RuleParser as RuleParser
import qualified Firerule.Format.ConfBuilder as ConfBuilder

data Config = Config {
        firewallFile :: String
    }

configParse = Config <$>
    Opt.strArgument (Opt.metavar "FILE")

main = do
    config <- Opt.execParser $
        Opt.info (configParse <**> Opt.helper) Opt.fullDesc
    SIO.withFile (firewallFile config) SIO.ReadMode $ \h -> do
        inp <- SIO.hGetContents h
        case RuleParser.parseFirewall inp >>= ConfBuilder.buildConf of
          Left err -> putStrLn $ Printf.printf "failure: %s" err
          Right fw -> Firewall.apply Iptables.IptablesFirewall fw
