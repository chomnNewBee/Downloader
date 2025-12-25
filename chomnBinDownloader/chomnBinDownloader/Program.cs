
using System.Net;
using Fiddler;

namespace chomnBinDownloader;
class Program
{
    const string defalutURL = "https://static.pg-demo.com";
    public static string? serverPath;
    public static string? localPath;
    public static string? remotePath = defalutURL;
    
    public static void Main(string[] args)
    {
        Console.WriteLine("请输入本地服务域名:");
        serverPath = Console.ReadLine();
        Console.WriteLine("请输入本地保存路径:");
        localPath = Console.ReadLine();
        
        localPath = localPath?.Replace('\\', '/');
        Console.WriteLine("保存的路径：" + localPath);
        
        Console.WriteLine("请输入远程资源服务器域名，默认为：https://static.pg-demo.com");
        remotePath = Console.ReadLine();

        if (!serverPath.IsValidString() || !localPath.IsValidString())
        {
            Console.WriteLine("本地服务域名和本地保存路径不能为空！");
            return;
        }

        if (!remotePath.IsValidString())
            remotePath = defalutURL;
        
        Console.WriteLine("远程资源服务器地址:" + remotePath);
        
        
        AppDomain.CurrentDomain.ProcessExit += new EventHandler(OnProcessExit);
        FiddlerApplication.Log.LogString($"安装证书,为了监听https请求");
        if (!CertMaker.rootCertExists())
        {
            if (!CertMaker.createRootCert())
                return;

            if (!CertMaker.trustRootCert())
                return;
        }

// 拦截请求响应
        FiddlerApplication.BeforeResponse  += session =>
        {
            if (serverPath != null && session.fullUrl.Contains(serverPath))
            {
                if (session.fullUrl.Contains(".bin"))
                {
                    OnHttpBin(session.fullUrl);
                    Console.WriteLine(session.fullUrl);
                }
                
                //Console.WriteLine(session.ResponseHeaders.HTTPResponseStatus);
            }
        };

        var settings = new FiddlerCoreStartupSettingsBuilder()
            .ListenOnPort(9898)
            .RegisterAsSystemProxy()
            .DecryptSSL()
            .OptimizeThreadPool() 
            .Build();

        CONFIG.IgnoreServerCertErrors = true;

        FiddlerApplication.Startup(settings);
        FiddlerApplication.Log.LogString($"Created endpoint listening on port {CONFIG.ListenPort}");

        Console.ReadLine();
        
    }

    private static void OnHttpBin(string url)
    {
        string remoteUrl = url.Replace(serverPath, remotePath);
        string savepath = url.Replace(serverPath, localPath);
        DownloadFile(remoteUrl, savepath);
        Console.WriteLine("下载："+remoteUrl+"成功！");
        Console.WriteLine("保存："+savepath+"成功！");

    }
    
    private static void OnProcessExit(object sender, EventArgs e)
    {
        // 在这里处理全局的关闭逻辑
        Console.WriteLine("应用程序正在全局范围内关闭！");
        if (FiddlerApplication.IsStarted()) {
            FiddlerApplication.oProxy.PurgeServerPipePool();
            FiddlerApplication.Shutdown();
        }
    }
    
    // 同步下载
    public static void DownloadFile(string url, string savePath)
    {
        using (WebClient client = new())
        {
            // 确保目录存在
            string directory = Path.GetDirectoryName(savePath);
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            try
            {
                client.DownloadFile(url, savePath);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            // 下载文件
        }
    }
  
  
}