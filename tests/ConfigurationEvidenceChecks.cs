using System;
using System.Linq;
using LocalLens;

class ConfigurationEvidenceChecks {
 static int count;
 static void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 static string[] Hosts(string text){return ConfigurationEvidence.ActiveUrls(text).Select(u=>u.Host).OrderBy(h=>h,StringComparer.Ordinal).ToArray();}
 static void Is(string text,string expected,string name){Check(String.Join(",",Hosts(text))==expected,name);}
 static int Main(){try{
  Is("index-url = https://pypi.tuna.tsinghua.edu.cn/simple","pypi.tuna.tsinghua.edu.cn","pip index URL is an active service value");
  Is("[global]\nextra-index-url=https://mirrors.aliyun.com/pypi/simple","mirrors.aliyun.com","pip extra index survives an INI section");
  Is("registry=https://registry.npmmirror.com/","registry.npmmirror.com","npm registry value is active");
  Is("@company:registry = https://registry.npmmirror.com/","registry.npmmirror.com","scoped npm registry is active");
  Is("URL = https://gitee.com/team/repository.git","gitee.com","unsectioned URL key is case insensitive");
  Is("# registry=https://registry.npmmirror.com\n ; index-url=https://mirrors.aliyun.com\n  # https://gitee.com","","full line comments never contribute URLs");
  Is("registry=https://registry.npmjs.org # example https://registry.npmmirror.com","registry.npmjs.org","inline hash comment URL is excluded");
  Is("index-url=https://pypi.org/simple ; https://mirrors.aliyun.com/pypi/simple","pypi.org","inline semicolon comment URL is excluded");
  Is("url = \"https://github.com/project;https://gitee.com/example\" # https://gitee.com","github.com","quoted URL path semicolon stays in the foreign URL");
  Is("registry = 'https://registry.npmjs.org/#https://registry.npmmirror.com' ; disabled https://gitee.com","registry.npmjs.org","quoted hash content is a fragment, not a second endpoint");
  Is("registry = \"https://registry.npmmirror.com/\" # documentation","registry.npmmirror.com","quoted active URL still parses");
  Is("documentation=https://gitee.com\nbackup-url=https://gitee.com\nAn example is https://gitee.com","","arbitrary text and unsupported keys are not active URL settings");
  Is(@"C:\Users\dev\.npmrc：registry=https://registry.npmjs.org # https://registry.npmmirror.com","registry.npmjs.org","collector prefix is removed before inline comment parsing");
  Is(@"C:\Users\dev\#notes\.npmrc：registry=https://registry.npmmirror.com","registry.npmmirror.com","hash in a collector file path is not a configuration comment");
  Is("[url \"https://github.com/\"]\n insteadOf=https://gitee.com/","github.com","Git alias source URL is not the actual rewritten destination");
  Is("[url \"https://gitee.com/\"]\n insteadOf=https://github.com/","gitee.com","Git domestic rewrite target is an active destination");
  Is("[url \"https://gitee.com/\"]\n pushInsteadOf=gh:","gitee.com","Git push rewrite target is active for a non-URL alias");
  Is("[url \"https://gitee.com/\"]\n # insteadOf=https://github.com/","","an unused Git URL subsection is not an active destination");
  Is("[url \"https://github.com/\"]\n insteadOf=https://example.org/ ; insteadOf=https://gitee.com/","github.com","Git rewrite comments cannot introduce a domestic destination");
  Is("[remote \"origin\"]\n url=https://gitee.com/team/repository.git","gitee.com","Git remote URL is an active destination");
  Is("[user]\n url=https://gitee.com\n insteadOf=https://gitee.com","","unknown Git user keys are not destination settings");
  Is("[user]\n registry=https://registry.npmmirror.com\n index-url=https://mirrors.aliyun.com","","known Git sections do not activate unrelated package-manager keys");
  Is("C:\\Users\\dev\\.gitconfig：registry=https://registry.npmmirror.com\nC:\\Users\\dev\\.gitconfig：url=https://gitee.com","","Git source profile rejects unrelated and unsectioned destination keys");
  Is("C:\\Users\\dev\\.npmrc：index-url=https://mirrors.aliyun.com\nC:\\Users\\dev\\.npmrc：channels: [https://mirrors.aliyun.com]","","npm source profile accepts registry keys rather than other file formats");
  Is("C:\\Users\\dev\\pip\\pip.ini：registry=https://registry.npmmirror.com\nC:\\Users\\dev\\pip\\pip.ini：extra-index-url=https://pypi.org/simple","pypi.org","pip source profile only accepts pip index settings");
  Is("C:\\Users\\dev\\.condarc：url=https://gitee.com\nC:\\Users\\dev\\.condarc：channels: [https://repo.anaconda.com]","repo.anaconda.com","Conda source profile only accepts channel settings");
  Is("channels:\n  - defaults\n  - https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main\n  - https://repo.anaconda.com/pkgs/main","mirrors.tuna.tsinghua.edu.cn,repo.anaconda.com","Conda block channel list reads only actual URL items");
  Is("channels:\n- https://mirrors.aliyun.com/anaconda/pkgs/main","mirrors.aliyun.com","Conda indentless sequence is accepted");
  Is("channels: [defaults, \"https://mirrors.tuna.tsinghua.edu.cn/anaconda\", 'https://repo.anaconda.com/pkgs/main'] # https://gitee.com","mirrors.tuna.tsinghua.edu.cn,repo.anaconda.com","Conda inline list retains quoted URLs and excludes trailing comment");
  Is("# channels:\n - https://gitee.com\nnotes:\n - https://gitee.com","","URL list items outside active channel context are excluded");
  Is("channels:\n  # - https://mirrors.aliyun.com\n  - https://repo.anaconda.com # https://mirrors.aliyun.com","repo.anaconda.com","channel comments cannot contribute domestic URLs");
  Is("channels:\n - https://repo.anaconda.com\nother:\n - https://gitee.com","repo.anaconda.com","a following setting ends the channel list");
  Is("custom_channels:\n  conda-forge: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud\nchannel_alias: https://repo.anaconda.com","mirrors.tuna.tsinghua.edu.cn,repo.anaconda.com","Conda custom channel map and alias URL are supported");
  Is("default_channels: [https://mirrors.aliyun.com/anaconda/pkgs/main]","mirrors.aliyun.com","Conda default channel list is active");
  Is("registry=https://registry.npmmirror.com\nregistry=https://registry.npmjs.org","registry.npmjs.org","later scalar assignment replaces an earlier setting");
  Is("channels: [https://mirrors.aliyun.com]\nchannels: [https://repo.anaconda.com]","repo.anaconda.com","later channel definition replaces an earlier list");
  Is("C:\\Users\\dev\\.condarc：channels:\nC:\\Users\\dev\\.npmrc：registry=https://registry.npmjs.org\nC:\\Users\\dev\\.condarc： - https://mirrors.aliyun.com","mirrors.aliyun.com,registry.npmjs.org","interleaved collector paths retain independent list state");
  Is("C:\\Users\\dev\\.gitconfig：[url \"https://github.com/\"]\nC:\\Users\\dev\\.npmrc：insteadOf=https://gitee.com/","","Git subsection state cannot leak to another collector source");
  Is("registry=https://example.org\nurl=https://user:password@gitee.com/repository\nindex-url=file:///C:/gitee.com\nextra-index-url=not-a-url","example.org","credential-bearing, non-HTTP and invalid values are excluded");
  Is("url=https://gitee.com.evil.example/path\nregistry=https://example.org/gitee.com","example.org,gitee.com.evil.example","URI parsing preserves exact host boundaries for the caller");
  Is("url=https://gitee.com\nurl=not-a-url","","an invalid replacement cannot keep a stale active URL");
  Is("registry=\"https://gitee.com","","unclosed quoted setting contributes no URL");
  Is("registry=https://registry.npmmirror.com\nregistry=\"https://registry.npmjs.org","","a malformed quoted replacement cannot preserve stale domestic evidence");
  Is("C:\\Users\\dev\\.npmrc：registry=https://registry.npmmirror.com\nC:\\Users\\dev\\.npmrc：registry=\"unterminated\nC:\\Users\\dev\\pip\\pip.ini：index-url=https://pypi.org/simple","pypi.org","a malformed source cannot invalidate independent valid configuration evidence");
  Check(!ConfigurationEvidence.ActiveUrls(new string('x',2*1024*1024+1)).Any(),"oversized evidence fails closed at the explicit input limit");
  Check(!ConfigurationEvidence.ActiveUrls("registry=https://gitee.com\n"+new string('x',8193)).Any(),"overlong configuration lines fail closed without parsing a truncated URL");
  Check(!ConfigurationEvidence.ActiveUrls(String.Concat(Enumerable.Repeat("# comment\n",10001))+"registry=https://gitee.com").Any(),"line limit never turns truncated configuration into active evidence");
  Console.WriteLine("CONFIGURATION EVIDENCE CHECKS PASSED: "+count);return 0;
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
