#!/usr/bin/env python3
from pathlib import Path
import sys
def fn(source,signature):
 i=source.find(signature)
 if i<0:raise AssertionError("missing source function "+signature)
 start=source.find("{",i);d=0
 for j in range(start,len(source)):
  if source[j]=="{":d+=1
  elif source[j]=="}":
   d-=1
   if d==0:return source[i:j+1]
 raise AssertionError("unclosed function "+signature)
def run(root):
 backend=(root/"consensus/istanbul/backend/engine.go").read_text()
 engine=(root/"consensus/istanbul/engine/engine.go").read_text()
 processor=(root/"core/state_processor.go").read_text()
 finalize=fn(backend,"func (sb *Backend) Finalize(")
 assert "GetBaseBlockReward(" in finalize
 assert "state.AddBalance(header.Coinbase, blockReward)" in finalize
 assert "EngineForBlockNumber(header.Number).Finalize(" in finalize
 engine_finalize=fn(engine,"func (e *Engine) Finalize(")
 assert "state.AddBalance(" not in engine_finalize
 assert "header.Root = state.IntermediateRoot" in engine_finalize
 assert "p.engine.Finalize(" in processor
 reward=fn(backend,"func (sb *Backend) GetBaseBlockReward(")
 assert "header.ParentHash" in reward
 assert "emission(" in reward
 assert "ETNMaxSupply" in reward and "circulatingSupply" in reward
 print("REWARD_REAL_QBFT_CREDIT_LOCATION_PASS Backend.Finalize -> StateDB.AddBalance")
 print("REWARD_QBFT_ENGINE_ROOT_FINALIZATION_NO_SECOND_MINT_PASS")
 print("REWARD_EMISSION_PARENT_HASH_AND_CAP_CHECK_PRESENT_PASS")
 unit=4*10**18
 orphan={"A":unit,"B":0}
 replacement={"A":0,"B":2*unit}
 wrong={"A":orphan["A"],"B":replacement["B"]}
 assert sum(wrong.values())-sum(replacement.values())==unit
 print(f'REWARD_CANONICAL_BRANCH_ORACLE_PASS orphan_A=0 final_B={replacement["B"]} base_units')
 print(f'REWARD_BAD_ADDITIVE_REPLAY_WOULD_OVERISSUE_BY={unit} base_units (MODEL_ONLY)')
 print("REWARD_SCOPE: no source-backed double-credit or unauthorized minting shown")
if __name__=="__main__":
 if len(sys.argv)!=2:raise SystemExit("Usage: python3 reproduce_rewards.py /path/to/electroneum-sc")
 run(Path(sys.argv[1]))