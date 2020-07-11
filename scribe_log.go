package scribe

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/psdshow/thrift_0_9_3_1"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func externalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		//检查这个接口在活动状态
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		//检查回环
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		//获取接口的地址
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		//获取ip
		for _, addr := range addrs {
			ip := getIpFromAddr(addr)
			if ip == nil {
				continue
			}
			return ip, nil
		}
	}
	return nil, errors.New("connected to the network?")
}

func getIpFromAddr(addr net.Addr) net.IP {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil // not an ipv4 address
	}

	return ip
}

func logFileLine(depth int) (string, int) {
	_, file, line, ok := runtime.Caller(2 + depth)
	if !ok {
		file = "???"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		if slash >= 0 {
			file = file[slash+1:]
		}
	}
	return file, line
}

type ScribeTrace struct {
	CurTimeStr    string       //当前时间
	HostName      string       //主机名称
	ServerName    string       //服务器名称
	IpAddr        string       //Ip地址
	UserAgent     string       //浏览器
	Referer       string       //访问来路
	AgencyId      string       //代理商ID
	AdvertiserId  string       //广告主ID
	SubaccoutId   string       //子账号ID
	AdminId       string       //管理员ID
	TraceId       string       //链路ID 32位
	TraceEvent    string       //链路事件
	LogModule     string       //日志目录模块
	RequestUrl    string       //请求的接口URL
	RequestParam  string       //接口的参数
	StatusCode    string       //接口状态码
	FileCode      string       //代码文件位置
	LineCode      string       //代码文件行数
	Message       string       //错误消息
	RunTime       string       //当前耗时
	TimeStamp     string       //当前时间戳微妙
	TimeStampMill string       //当前时间戳ms
	SpanId        string       //日志自己的标识ID,//这里用thread_id
	PerentId      string       //层级关系,//这里我们用pid来填充
	LogLevel      string       //日志级别，大写:DEBUG/INFO/ERROR/CRIT
	curtime       time.Time    //记录接收到请求处理请求的开始的时间
	scribeLoger   *ScribeLoger //打印日志用的scribe对象
}

func NewScribeTrace(scribeLoger *ScribeLoger, trace_id, trace_event, log_perent_id, log_id, log_module string, http_r *http.Request) *ScribeTrace {
	scribeTrace := &ScribeTrace{}
	if http_r != nil {
		scribeTrace.UserAgent = http_r.UserAgent()
		scribeTrace.Referer = http_r.Referer()
		scribeTrace.RequestUrl = http_r.URL.String()
	}
	//主机信息
	scribeTrace.HostName, _ = os.Hostname()
	Ip, _ := externalIP()
	scribeTrace.IpAddr = Ip.String()
	scribeTrace.ServerName = os.Getenv("server_name")
	//链路相关信息
	scribeTrace.TraceId = trace_id
	scribeTrace.TraceEvent = trace_event
	//用于日志跟踪用的
	scribeTrace.PerentId = log_perent_id
	scribeTrace.SpanId = log_id
	//
	scribeTrace.LogModule = log_module
	//记录时间
	scribeTrace.curtime = time.Now()
	//记录全局对象
	scribeTrace.scribeLoger = scribeLoger
	return scribeTrace
}

//设置账号相关的信息
func (this *ScribeTrace) SetAccountId(advertiser_id, subaccount_id, admin_id string) {
	this.AdvertiserId = advertiser_id
	this.SubaccoutId = subaccount_id
	this.AdminId = admin_id
}

func (this *ScribeTrace) String() string {
	//（各字段详细意义见scribe日志规范文档）：
	//        time,hostname,server_name,ip,user_agent,referer,agency_id,advertiser_id,subaccount_id,admin_id,trace_id,
	//        trace_event,log_module,request_url,request_param,status_code,file,line,message,run_time
	// log_key := [...]string{"time", "hostname", "server_name",
	// 	"ip", "user_agent", "referer", "agency_id", "advertiser_id", "subaccount_id", "admin_id",
	// 	"trace_id", "trace_event", "log_module", "request_url", "request_param", "status_code",
	// 	"file", "line", "message", "run_time"}
	currentTime := time.Now()
	this.CurTimeStr = currentTime.String()
	//耗时
	this.RunTime = fmt.Sprintf("%f", currentTime.Sub(this.curtime).Seconds())
	this.curtime = currentTime
	//时间戳

	logs := []string{this.CurTimeStr, this.HostName, this.ServerName,
		this.IpAddr, this.UserAgent, this.Referer, this.AgencyId, this.AdminId,
		this.TraceId, this.TraceEvent, this.LogModule, this.RequestUrl,
		this.RequestParam, this.StatusCode, this.FileCode, this.LineCode, this.Message,
		this.RunTime, this.TimeStamp, this.TimeStampMill, this.SpanId, this.PerentId,
		this.LogLevel}
	log := strings.Join(logs, "\\01")
	// fmt.Printf("%s\n", log)
	return log
}

func (this *ScribeTrace) formatMessage(format string, args ...interface{}) string {
	log_message_buf := new(bytes.Buffer)
	fmt.Fprintf(log_message_buf, format, args...)
	return log_message_buf.String()
}

func (this *ScribeTrace) WriteScribe(log_level string, format string, args ...interface{}) {
	//日志信息
	file, line := logFileLine(0)
	this.FileCode = file
	this.LineCode = fmt.Sprintf("%d", line)
	//打印日志的
	this.LogLevel = log_level
	//将最后要打印的日志打印出来
	this.Message = this.formatMessage(format, args...)

	//打印日志
	if this.scribeLoger != nil {
		this.scribeLoger.WriteScribeLoger(this.LogModule, this.String())
	}
}

func (this *ScribeTrace) WriteScribeEx(code_file, code_line, log_level string, format string, args ...interface{}) {
	//打印日志的
	this.FileCode = code_file
	this.LineCode = code_line
	this.LogLevel = log_level
	this.Message = this.formatMessage(format, args...)

	//打印日志
	if this.scribeLoger != nil {
		this.scribeLoger.WriteScribeLoger(this.LogModule, this.String())
	}
}

//调用scribe
type ScribeLoger struct {
	client          Scribe
	protocolFactory thrift.TProtocolFactory
	trans           thrift.TTransport
}

func NewScribeLoger(host, port string) (*ScribeLoger, error) {
	scribeLoger := &ScribeLoger{}
	var trans thrift.TTransport
	//先创建一个socket
	trans, err := thrift.NewTSocket(net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error resolving address:", err)
		return scribeLoger, err
	}

	//打开framed传输方式
	trans = thrift.NewTFramedTransport(trans)
	//仅仅使用二进制协议
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	//创建一个client
	client := NewScribeClientFactory(trans, protocolFactory)
	if err := trans.Open(); err != nil {
		fmt.Fprintln(os.Stderr, "Error opening socket to ", host, ":", port, " ", err)
		return scribeLoger, err
	}
	//将基本的参数进行记录存储，后期释放资源以及打印scribe的时候会用到
	scribeLoger.client = client
	scribeLoger.protocolFactory = protocolFactory
	scribeLoger.trans = trans
	return scribeLoger, nil
}

func (this *ScribeLoger) Close() {
	this.trans.Close()
}

func (this *ScribeLoger) WriteScribeLoger(catalog, logstr string) {
	logEntry := NewLogEntry()
	logEntry.Category = catalog
	logEntry.Message = logstr

	if this.client != nil {
		rscode, err := this.client.Log([]*LogEntry{logEntry})
		if rscode != ResultCode_OK {
			fmt.Fprintln(os.Stderr, "write scribeloger failed:", rscode.String())
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "write scribeloger err:", err)
		}
	}
}

func TestScribeMain() {
	scribeLoger, err := NewScribeLoger("192.168.10.206", "1463")
	if err != nil {
		fmt.Fprintln(os.Stderr, "the scribe init failed:", err)
		return
	}
	pid := strconv.FormatInt(int64(os.Getpid()), 10)
	tid := strconv.FormatInt(int64(os.Getppid()), 10)

	scribeTrace := NewScribeTrace(scribeLoger, "traceId", "traceEvent", pid, tid, "go_test", nil)
	scribeTrace.WriteScribe("ERROR", "this is for scribe test")

	scribeLoger.Close()
}
