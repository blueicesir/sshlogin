// 通过ssh批量执行相关指令，用于自动化运维。
// ssh批量运维程序
// 2024年11月21日 - 
// 导入ed25519mod模块从本地路径
// cd /d D:\Doc\Dropbox\Project\Go\sshunittest
// go mod edit -require github.com/blueicesir/ed25519mod@v0.0.1
// go mod edit -replace github.com/blueicesir/ed25519mod@v0.0.1=./ed25519mod

package sshlogin

import (
    "fmt"
    "golang.org/x/crypto/ssh"
    "time"
    "bytes"
    "strings"
    "io"
    "errors"
)

type AuthModel int8

const (
    PASSWORD AuthModel = iota + 1
    PUBLICKEY
)

// SSHConfig 存储 SSH 连接配置
type SSHConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    Timeout  time.Duration
    AuthModel AuthModel
    PrivateKey string
}

type SSHExpect struct {
    cfg SSHConfig
    ssh_config *ssh.ClientConfig
    client *ssh.Client
    session *ssh.Session
    stdinPipe io.WriteCloser
    stdoutBuf bytes.Buffer
    stderrBuf bytes.Buffer
    pre_stdout_offset int
    pre_stderr_offset int
    exec_last_delay time.Duration
    exec_init_delay time.Duration
    terminal_height int
    terminal_width int
}


func (s *SSHExpect) WindowChange(height,width int) error{
    if height>0 && width>0 {
        s.session.WindowChange(height,width)
        return nil
    }
    return errors.New("WindowChange height and width must big zero.")
}


func (s *SSHExpect) Connect(cfg SSHConfig) ([]string,error) {
    output:=[]string{}
    var err error
    s.cfg=cfg
    s.pre_stdout_offset=0
    s.pre_stderr_offset=0

    s.terminal_height=150
    s.terminal_width=300

    // Run函数执行最后一次等待相对长一些时间，等待可能的stdout的输出
    s.exec_last_delay=time.Millisecond*time.Duration(100)

    // 默认Run执行指令前执行的延时，默认300毫秒
    s.exec_init_delay=time.Millisecond*time.Duration(300)

    s.ssh_config=&ssh.ClientConfig{
        Timeout: s.cfg.Timeout,
        User: s.cfg.Username,
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    switch cfg.AuthModel {
    case PASSWORD:
        s.ssh_config.Auth=[]ssh.AuthMethod{ssh.Password(s.cfg.Password)}
    case PUBLICKEY:
        key:=s.cfg.PrivateKey
        var signer ssh.Signer
        if s.cfg.Password==""{
            signer,err=ssh.ParsePrivateKey([]byte(key))
            if err!=nil{
                return output,fmt.Errorf("SSHExpect::Connect ssh.ParsePrivateKey fail,%v",err)
            }
        }else{
            signer,err=ssh.ParsePrivateKeyWithPassphrase([]byte(key),[]byte(s.cfg.Password))
            if err!=nil{
                return output,fmt.Errorf("SSHExpect::Connect ssh.ParsePrivateKeyWithPassphrase fail,%v",err)
            }
        }
        s.ssh_config.Auth=[]ssh.AuthMethod{ssh.PublicKeys(signer)}
    }

    s.client,err=ssh.Dial("tcp",fmt.Sprintf("%s:%d",s.cfg.Host,s.cfg.Port),s.ssh_config)
    if err!=nil{
        return output,fmt.Errorf("SSHExpect::Connect ssh.Dial fail,%v",err)
    }

    s.session,err=s.client.NewSession()
    if err!=nil {
        return output,fmt.Errorf("SSHExpect::Connect cli.NewSession fail,%v",err)
    }

    s.stdinPipe,err=s.session.StdinPipe()
    if err!=nil{
        return output,fmt.Errorf("SSHExpect::Connect sess.StdinPipe fail,%v",err)
    }

    s.session.Stdout=&s.stdoutBuf
    s.session.Stderr=&s.stderrBuf

    modes:=ssh.TerminalModes {
        ssh.ECHO:1,
        ssh.TTY_OP_ISPEED: 14400,
        ssh.TTY_OP_OSPEED: 14400,
    }

    // xterm
    // xterm-256color
    if err:=s.session.RequestPty("xterm",s.terminal_height,s.terminal_width,modes);err!=nil{
        return output,fmt.Errorf("SSHExpect::Connect request pty error:%v",err)
    }

    if err:=s.session.Shell();err!=nil{
        return output,fmt.Errorf("SSHExpect::Connect start shell error:%v",err)
    }

    // 需要休眠一段时间，保证登录成功，这个值可能还需要增加
    time.Sleep(time.Second)
    rts:=s.stdoutBuf.String()
    s.pre_stdout_offset=len(rts)
    rs_lines:=[]string{}
    output=strings.Split(rts,"\n")
    for i:=range output{
        tmp_line:=strings.TrimSpace(output[i])
        if len(tmp_line)>0{
            rs_lines=append(rs_lines,tmp_line)
        }
    }
    return rs_lines,nil
}


func (s *SSHExpect) Close(){
    defer func(){
        if s.session!=nil {
            s.session.Close()
        }
    }()
    defer func(){
        if s.client!=nil{
            s.client.Close()
        }
    }()
}

// 手动修改最后一次执行等待的时间，默认为100毫秒
func (s *SSHExpect) SetRunLastDelay(delay time.Duration){
    s.exec_last_delay=delay
}


// 运行一个或多个命令
func (s *SSHExpect) Run(cmds []string,timeout time.Duration) ([]string,error){
    // 休眠300毫秒
    delay:=s.exec_init_delay // time.Millisecond*time.Duration(300)
    done:=make(chan bool)
    go func(){
        time.Sleep(delay)
        for ic:=range cmds {
            _,err:=s.stdinPipe.Write([]byte(fmt.Sprintf("%s\n",cmds[ic])))
            if err!=nil{
                fmt.Printf("SSHExpect::write command %s error:%v\n",cmds[ic],err)
                break
            }
            time.Sleep(delay)
        }

        // 最后一次延时多100毫秒
        time.Sleep(s.exec_last_delay)
        done<-true
    }()

    go func(){
        s.session.Wait()
        done<- true
    }()

    select {
    case <-done:
        // 命令执行完成,获取标准输出的文字内容
        rts:=s.stdoutBuf.String()
        if s.pre_stdout_offset==0{
            s.pre_stdout_offset=len(rts)
            return s.Split(rts),nil
        }else{
            tmp_offset:=s.pre_stdout_offset
            s.pre_stdout_offset=len(rts)
            return s.Split(rts[tmp_offset:]),nil
        }
    case <-time.After(timeout): // 10*time.Second
        return []string{},fmt.Errorf("Command execution timeout %v",timeout)
    }
}

func (s *SSHExpect) Split(input string) []string {
    rt_output:=[]string{}
    output:=strings.Split(input,"\n")
    for i:=range output{
        tmp:=strings.TrimLeft(strings.TrimSpace(output[i]),"]0;")
        rt_output=append(rt_output,tmp)
        // if strings.Index(tmp,"")==-1 {
        //     rt_output=append(rt_output,tmp)
        // }else{
        //     output2:=strings.Split(tmp,"")
        //     index:=0
        //     for i2:=range output2 {
        //         if index>0{
        //             rt_output=append(rt_output,output2[i2])
        //         }
        //         index++
        //     }
        // }
    }

    if len(rt_output)>1{
        // 丢弃最后一行的命令提示符号
        return rt_output[:len(rt_output)-1]
    }else{
        return rt_output
    }
    return rt_output
}


// 检查字符串数组中是否存在查找的关键字，此函数区分大小写
// 返回值为一个整数，-1表示不存在。
func (s *SSHExpect) Contains(lines []string,keyword string) int {
    for i:=range lines{
        if strings.Contains(lines[i],keyword) {
            return i
        }
    }
    return -1
}

func (s *SSHExpect) Display(out []string) {
    for i:=range out{
        // 对于没有数据的行进行忽略
        line:=strings.TrimSpace(out[i])
        if len(line)>0{
            fmt.Println(line)
        }
    }
}


func Display(out []string){
    for i:=range out{
        // 对于没有数据的行进行忽略
        line:=strings.TrimSpace(out[i])
        if len(line)>0{
            fmt.Println(line)
        }
    }
}



// 使用证书验证登录测试
func SshLogin(host_ip string,host_port int,login_user string,login_password string,privatekey string,cmds []string) ([]string,error) {
    var err error
    output:=[]string{}
    // ~/.ssh/authorized_keys文件必须和归属用户的宿主一致，否则无法读取。
    cfg:=SSHConfig{
        Host: host_ip,
        Port:     host_port,
        AuthModel: PUBLICKEY, // 当这个为PUBLICKEY时，Password是证书的解密密码,而不是ssh登录的密码
        Username: login_user, // 记住这个用户是支持公钥登录的给用户
        Password: login_password, // 解密失败会提示 ssh.ParsePrivateKeyWithPassphrase fail,x509: decryption password incorrect
        Timeout:  20 * time.Second,
        PrivateKey: privatekey, // 当设置了私钥时默认使用私钥登录，如果私钥为""空字符串则使用密码登录
    }

    // 如果私钥为空，则使用密码登录
    if cfg.PrivateKey=="" {
        cfg.AuthModel=PASSWORD
    }

    se:=&SSHExpect{}
    defer se.Close()
    output,err=se.Connect(cfg)
    if err!=nil{
        return output,fmt.Errorf("SshLogin Connect fail,%v",err)
    }

    output,err=se.Run(cmds,time.Second*time.Duration(10))
    if err!=nil{
        return output,fmt.Errorf("SshLogin Run command fail,%v",err)
    }
    return output,nil
}


/*
func main(){
    // 公钥登录
    private_key:=`-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----`
    output,err:=SshLogin("10.180.68.220",22,"blueice","BlueLinux",private_key,[]string{"whoami","sudo -s","whoami","uname -na"})

    // // 密码登录
    // output,err:=SshLogin("10.180.68.220",22,"fsp","XxXxXxXxXxXx","",[]string{"whoami","uname -na"})

    if err!=nil{
        fmt.Println(err)
    }else{
        Display(output)
    }
}
*/