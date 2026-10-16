using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;
namespace LocalLens {
 // Geographic evidence only: no coordinate is sent to a remote geocoder.
 public static class ChinaGeography {
  static readonly Lazy<double[][][]> polygons=new Lazy<double[][][]>(Load);
  static double[][][] Load(){
   using(var stream=typeof(ChinaGeography).Assembly.GetManifestResourceStream("china-boundary.json")){
    if(stream==null)throw new InvalidDataException("缺少离线地域数据");
    using(var reader=new StreamReader(stream)){
     var root=new JavaScriptSerializer{MaxJsonLength=4*1024*1024,RecursionLimit=64}.Deserialize<Dictionary<string,object>>(reader.ReadToEnd());
     var geometry=(Dictionary<string,object>)root["geometry"];var result=new List<double[][]>();
     foreach(IList polygon in (IList)geometry["coordinates"]){foreach(IList ring in polygon){var points=new List<double[]>();foreach(IList p in ring)points.Add(new[]{Convert.ToDouble(p[0],CultureInfo.InvariantCulture),Convert.ToDouble(p[1],CultureInfo.InvariantCulture)});result.Add(points.ToArray());}}
     return result.ToArray();
    }
   }
  }
  // null = reported uncertainty or conservative 2 km map margin intersects a boundary.
  public static bool? IsMainland(double latitude,double longitude,double accuracyMeters){
   if(Double.IsNaN(latitude)||Double.IsNaN(longitude)||Double.IsInfinity(latitude)||Double.IsInfinity(longitude)||Math.Abs(latitude)>90||Math.Abs(longitude)>180||Double.IsNaN(accuracyMeters)||Double.IsInfinity(accuracyMeters)||accuracyMeters<0)throw new FormatException("坐标或精度无效");
   bool inside=false;double nearest=Double.MaxValue,scaleX=111320*Math.Cos(latitude*Math.PI/180),scaleY=111320;
   foreach(var ring in polygons.Value){bool inRing=false;for(int i=0,j=ring.Length-1;i<ring.Length;j=i++){
    double xi=ring[i][0],yi=ring[i][1],xj=ring[j][0],yj=ring[j][1];
    if((yi>latitude)!=(yj>latitude)&&longitude<(xj-xi)*(latitude-yi)/(yj-yi)+xi)inRing=!inRing;
    double ax=(xi-longitude)*scaleX,ay=(yi-latitude)*scaleY,bx=(xj-longitude)*scaleX,by=(yj-latitude)*scaleY,dx=bx-ax,dy=by-ay;
    double t=dx*dx+dy*dy==0?0:Math.Max(0,Math.Min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy)));
    nearest=Math.Min(nearest,Math.Sqrt((ax+t*dx)*(ax+t*dx)+(ay+t*dy)*(ay+t*dy)));
   }if(inRing)inside=!inside;}
   return nearest<=Math.Max(2000,accuracyMeters)?(bool?)null:inside;
  }
 }
}
