namespace LocalLens {
 public static class ClueRules {
  public static string ForId(int id){return ChinaEvidence.Rule(id);}
  public static Finding Information(int id,string text,string summary){return ChinaEvidence.Apply(new Finding{Id=id,State="信息",Summary=summary,Evidence=text??"",Coverage="本机读取结果 / 中国用户关联审查"});}
 }
}