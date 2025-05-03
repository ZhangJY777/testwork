package web

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/md5"
    ra "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    _ "github.com/go-sql-driver/mysql"
    shell "github.com/ipfs/go-ipfs-api"
    "html/template"
    "io/ioutil"
    "math/big"
    "math/rand"
    "net/http"
    "path/filepath"
    "strconv"
    "testwork/sdkInit"
    "time"
)


type FileData struct {
    Id                  string `json:"id"`
    Filename            string `json:"filename"`
    FileDetail          string `json:"filedetail"`
    FileHash            string `json:"fileHash"`
    CreateDate          string `json:"createDate"`
    Username            string `json:"username"`
    Times               string `json:"times"`
    Card                string `json:"card"`
    User                []string `json:"user"`
    Filepath            string `json:"filepath"`
    IpfsHash            string `json:"ipfsHash"`
    Time                string `json:"time"`
    Date                string `json:"date"`
    Money               string `json:"money"`
    Money1               string `json:"money1"`
    End                  string `json:"end"`
    TransferDate        string `json:"transferdate"`
    Flag                string `json:"flag"`
    Tmp                string `json:"tmp"`
}
type UserTmpDetail struct {
    Id           string
    Name         string
    Age          int
    IDCard       string
    Organization string
    Flag         string
}
type Transaction struct {
    Id                  string `json:"id"`
    Filename            string `json:"filename"`
    Date                string `json:"date"`
    Username            string `json:"username"`
    User                string `json:"user"`
    Username1           string `json:"username1"`
    User1               string `json:"user1"`
    Money               string `json:"money"`
    Money1               string `json:"money1"`
    FileHash               string `json:"fileHash"`
    Flag                string `json:"flag"`
}
type Login struct {
    name          string
    password      string
}
type Wallet struct {
    Id           string
    Address      string
    Money        string
}
type Ticket struct {
    Hash          string `json:"hash"`
    Money         string `json:"money"`
    Time          string `json:"time"`
    Content       string `json:"content"`
}

type User struct {
    Id             string
    Money          string
}
// 环签名结构
type RingSignature struct {
    PublicKeys []*ecdsa.PublicKey // 环中的公钥集合
    C          *big.Int           // 挑战值
    S          []*big.Int         // 签名值集合
}
// //全局sdk变量 来操作链码
var App sdkInit.Application
//全局变量CA
var db *sql.DB
var sh *shell.Shell


func UploadIPFS(str string) string {
    sh = shell.NewShell("localhost:5001")
    hash, err := sh.Add(bytes.NewBufferString(str))
    if err != nil {
        fmt.Println("ipfs错误：", err)
    }
    return hash
}


//从ipfs下载数据
func CatIPFS(hash string) string {
    sh = shell.NewShell("localhost:5001")
    read, err := sh.Cat(hash)
    if err != nil {
        fmt.Println(err)
    }
    body, err := ioutil.ReadAll(read)
    return string(body)
}

func initDB() (err error) {
    // DSN:Data Source Name
    dsn := "root:root123@tcp(localhost:3306)/Data"
    // 不会校验账号密码是否正确
    db, err = sql.Open("mysql", dsn)
    if err != nil {
        return err
    }
    // 尝试与数据库建立连接（校验dsn是否正确）
    err = db.Ping()
    if err != nil {
        return err
    }
    return nil
}
//渲染模版
func ShowView(w http.ResponseWriter, r *http.Request, templateName string, data interface{})  {
    // 指定视图所在路径
    pagePath := filepath.Join("web/", templateName)
    resultTemplate, err := template.ParseFiles(pagePath)
    if err != nil {
        fmt.Printf("Error creating template instance: %v", err)
        return
    }
    //渲染模版
    err = resultTemplate.Execute(w, data)
    if err != nil {
        fmt.Printf("An error occurred while fusing data in the template: %v", err)
        return
    }
}
//将字符串进行md5加密
func MD5(str string) string {
    data := []byte(str) //切片
    has := md5.Sum(data)
    md5str := fmt.Sprintf("%x", has) //将[]byte转成16进制
    return md5str
}
func in(target string, str_array []string) bool {
    for _, element := range str_array{
        if target == element{
            return true
        }
    }
    return false
}
//admin
//登录函数
func a_login(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    index := r.FormValue("index")
    //输入为空 则返回原页面
    if username == "" && index == "" {
        ShowView(w, r, "admin/login.html", 0)
        //index也是返回原页面
    }else if index == "logout"{
        c := http.Cookie{
            Name: "name",
            Value: "",
        }
        //设置cookie
        http.SetCookie(w, &c)
        ShowView(w, r, "admin/login.html", 0)
    }else{
        //其他情形 判断是否账号密码一样
        var l Login
        var uid string
        var flag string
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        defer db.Close()
        sql := "SELECT password,uid,flag FROM user WHERE username = '" + username +"'"
        // fmt.Println(sql)
        //查询
        err = db.QueryRow(sql).Scan(&l.password, &uid, &flag)
        // fmt.Println(l.password)
        if err != nil {
            fmt.Println("login failed, err:%v\n", err)
        }
        if flag != "Finish"{
            ShowView(w, r, "admin/login.html", 2)
            return
        }
        //判断
        if password == l.password{
            c := http.Cookie{
                Name: "name",
                Value: uid,
            }
            //登录成功后 设置cookie
            http.SetCookie(w, &c)
            ShowView(w, r, "admin/login.html", 1)
        }else{
            ShowView(w, r, "admin/login.html", 2)
        }
    }
}

//注册
//用户进行注册
func a_register(w http.ResponseWriter, r *http.Request){
    name := r.FormValue("username")
    passwd := r.FormValue("password")
    uname := r.FormValue("uname")
    card := r.FormValue("card")
    organization := r.FormValue("organization")
    fmt.Println(name, passwd, uname)
    rands := time.Now().Format("2006/01/02 15:04:05") + strconv.Itoa(rand.Intn(100))
    uid := "U-" + MD5(rands)
    sqlStr := "insert into user(uid, username, name, card, organization, password,flag) values (?,?,?,?,?,?,?)"

    err := initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
    }
    _, err = db.Exec(sqlStr, uid, name,uname,card, organization, passwd,"Unfinished")
    if err != nil {
        fmt.Errorf("insert failed, err:%v\n", err)
    }

    opera := []string{"setMoney", uid, "100", "init"}
    _, err = App.SetV(opera)
    if err != nil {
        fmt.Errorf("read failed, err:%v\n", err)
        fmt.Fprintln(w, "注册失败！")
        return
    }
    fmt.Fprintln(w, "注册成功！等待审核！")
}

//获取cookie
//根据cookie判断权限 然后进行相应的跳转
func a_index(w http.ResponseWriter, r *http.Request) {
    name, err := r.Cookie("name")
    if err != nil {
        ShowView(w, r, "admin/403.html", nil)
        return
    } else if name.Value == ""{
        ShowView(w, r, "admin/403.html", nil)
    } else {
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        var utd UserTmpDetail
        sql := "SELECT username, name, level FROM user WHERE uid = '" + name.Value + "'"
        err = db.QueryRow(sql).Scan(&utd.IDCard, &utd.Name, &utd.Flag)
        utd.Id = utd.IDCard[0:1]
        if utd.Flag == "消费者"{
            utd.Flag = "0"
        }else {
            utd.Flag = "1"
        }
        ShowView(w, r, "admin/index.html", utd)
    }
}
func a_tickit(w http.ResponseWriter, r *http.Request){
    var ticket Ticket
    money := r.FormValue("money")
    ticket.Hash = MD5("ticket")
    ticket.Time = time.Now().Format("2006/01/02 15:04:05")
    ticket.Money = money
    putData, err := json.Marshal(ticket)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
    }
    encodeData := base64.StdEncoding.EncodeToString(putData)
    ticket.Content = encodeData
    //fmt.Fprintln(w, "充值券: " + string(encodeData))
    ShowView(w, r, "admin/faq.html", ticket)
}
func a_money(w http.ResponseWriter, r *http.Request){
    var ticket Ticket
    cookie,_ :=r.Cookie("name")
    name := r.FormValue("money")
    decodeDataByteArr, err := base64.StdEncoding.DecodeString(name)
    if err != nil {
        fmt.Errorf("Failed to get asset: %s", err)
    }
    err = json.Unmarshal(decodeDataByteArr, &ticket)
    if ticket.Hash != MD5("ticket"){
        fmt.Errorf("setMoney failed, err:%v\n", err)
        fmt.Fprintln(w, "充值失败！")
        return
    }
    opera := []string{"setMoney", cookie.Value, ticket.Money, "up"}
    _, err = App.SetV(opera)
    if err != nil {
        fmt.Errorf("setMoney failed, err:%v\n", err)
        fmt.Fprintln(w, "充值失败！")
        return
    }
    fmt.Fprintln(w, "充值成功！")
}
func a_confirm(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    var fd FileData
    opera := []string{"getFileDetail", name}
    value, err := App.Get(opera)
    if err != nil {
        fmt.Errorf("get failed, err:%v\n", err)
    }
    err = json.Unmarshal([]byte(value), &fd)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
    }

    ShowView(w, r, "admin/provePrint.html", fd)
}
//路由
func a_search(w http.ResponseWriter, r *http.Request) {
    content := r.FormValue("content")
    err := initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
        return
    }
    var uids []string
    sql := "SELECT uid FROM transfer WHERE name like '%" + content + "%'"
    rows, err := db.Query(sql)
    for rows.Next() {
        var uid string
        err = rows.Scan(&uid)
        if err != nil {
            panic(err)
        }
        uids = append(uids, uid)
    }
    var fileDatas []FileData
    var nfileDatas []FileData
    opera := []string{"getFileData", ""}
    value, err := App.Get(opera)
    if err != nil {
        fmt.Errorf("getFileData failed, err:%v\n", err)
        //return
    }
    err = json.Unmarshal([]byte(value), &fileDatas)
    if err != nil {
        fmt.Errorf("json failed, err:%v\n", err)
        //return
    }
    for _, uid := range uids {
        for _, fd := range fileDatas {
            if len(fd.User) > 1 {
                fd.Flag = "竞拍中"
            }
            if uid == fd.Id {
                nfileDatas = append(nfileDatas, fd)
            }
        }
    }
    ShowView(w, r, "admin/project.html", nfileDatas)
}
func a_delete(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    cookie, _ := r.Cookie("name")
    err := initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
        return
    }
    defer db.Close()
    sql := "DELETE FROM transfer WHERE uid = '"+ name +"'"
    _, err = db.Exec(sql)
    if err != nil {
        fmt.Println("delet failed, err:%v\n", err)
    }
    opera := []string{"delete", name,time.Now().Format("2006/01/02")}
    _, err = App.Set(opera)
    if err != nil {
        fmt.Errorf("setMoney failed, err:%v\n", err)
        fmt.Fprintln(w, "失败！")
        return
    }
    var fileDatas []FileData
    var nfileDatas []FileData
    opera = []string{"getFileData", ""}
    value, err := App.Get(opera)
    if err != nil {
        fmt.Errorf("getFileData failed, err:%v\n", err)
        //return
    }
    err = json.Unmarshal([]byte(value), &fileDatas)
    if err != nil {
        fmt.Errorf("json failed, err:%v\n", err)
        //return
    }
    //not 未竞拍
    for _,fd := range fileDatas{
        if fd.Flag == "未竞拍"{
            continue
        }
        l := len(fd.User)
        if cookie.Value == fd.User[l-1] {
            nfileDatas = append(nfileDatas, fd)
        }
    }
    ShowView(w, r, "admin/projects.html", nfileDatas)
}
func a_route(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    cookie, _ := r.Cookie("name")
    //name为list 则展示所有的项目
    if name == "lists" {
        var fds []FileData
        opera := []string{"getTransaction", "Tmp-"+cookie.Value}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("get failed, err:%v\n", err)
        }
        err = json.Unmarshal([]byte(value), &fds)
        if err != nil {
            fmt.Errorf("Failed to json asset: %s", err)
        }
        ShowView(w, r, "admin/lists.html", fds)
    } else if name == "confirm"{
        var fileDatas []FileData
        var nfileDatas []FileData
        opera := []string{"getFileData", ""}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("getFileData failed, err:%v\n", err)
            //return
        }
        err = json.Unmarshal([]byte(value), &fileDatas)
        if err != nil {
            fmt.Errorf("json failed, err:%v\n", err)
            //return
        }
        //show
        for _,fd := range fileDatas{
            if cookie.Value == fd.User[0]{
                nfileDatas = append(nfileDatas, fd)
            }
        }
        ShowView(w, r, "admin/confirm.html", nfileDatas)
    } else if name == "transaction"{
        var fileDatas []FileData
        var nfileDatas []FileData
        opera := []string{"getFileData", ""}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("getFileData failed, err:%v\n", err)
            //return
        }
        err = json.Unmarshal([]byte(value), &fileDatas)
        if err != nil {
            fmt.Errorf("json failed, err:%v\n", err)
            //return
        }
        //show transaction
        for _,fd := range fileDatas{
            if cookie.Value == fd.User[0]{
                if fd.Flag == "竞拍中"{
                    nfileDatas = append(nfileDatas, fd)
                }
            }
        }
        ShowView(w, r, "admin/process.html", nfileDatas)
    } else if name == "operation"{
        var fileDatas []FileData
        var nfileDatas []FileData
        opera := []string{"getFileData", ""}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("getFileData failed, err:%v\n", err)
            //return
        }
        err = json.Unmarshal([]byte(value), &fileDatas)
        if err != nil {
            fmt.Errorf("json failed, err:%v\n", err)
            //return
        }
        //not 未竞拍
        for _,fd := range fileDatas{
            if fd.Flag == "未竞拍"{
                continue
            }else if fd.Flag == "竞拍中"{
                l := len(fd.User)
                if cookie.Value == fd.User[l-1] {
                    nfileDatas = append(nfileDatas, fd)
                }
            }

        }
        ShowView(w, r, "admin/projects.html", nfileDatas)
    } else if name == "info"{
        var fileDatas []FileData
        var nfileDatas []FileData
        opera := []string{"getFileData", ""}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("getFileData failed, err:%v\n", err)
            //return
        }
        err = json.Unmarshal([]byte(value), &fileDatas)
        if err != nil {
            fmt.Errorf("json failed, err:%v\n", err)
            //return
        }
        for _,fd := range fileDatas{
            if fd.Flag == "竞拍中" {
                var level string
                err = initDB()
                if err != nil {
                    fmt.Println("init failed, err:%v\n", err)
                    return
                }
                sql := "SELECT level FROM user WHERE uid = '" + cookie.Value +"'"
                // fmt.Println(sql)
                //查询
                err = db.QueryRow(sql).Scan(&level)
                // fmt.Println(l.password)
                if err != nil {
                    fmt.Println("login failed, err:%v\n", err)
                }
                if level == "商家"{
                    fd.Card = "none"
                }
                nfileDatas = append(nfileDatas, fd)
            }
        }
        ShowView(w, r, "admin/project.html", nfileDatas)
    } else if name == "add"{
        ShowView(w, r, "admin/add.html", nil)
    } else if name == "recharge"{
        var wallet Wallet
        opera := []string{"getMoney", cookie.Value, "-1"}
        value, _ := App.GetV(opera)
        wallet.Money = value
        wallet.Id = cookie.Value
        wallet.Address = MD5(wallet.Id)
        ShowView(w, r, "admin/wallet.html", wallet)
    }

}
func a_recharge(w http.ResponseWriter, r *http.Request) {
    ShowView(w, r, "admin/recharge.html", nil)
}

func a_transfer(w http.ResponseWriter, r *http.Request) {
    uid := r.FormValue("uid")
    cid := r.FormValue("cid")
    money := r.FormValue("money")
    name := r.FormValue("name")
    h := r.FormValue("end")
    date := time.Now().Format("2006/01/02")
    i,_ := strconv.Atoi(h)
    now := time.Now()
    duration := i * 24 * 3600000000000
    // 计算三天后的时间
    end := now.Add(time.Duration(duration))
    opera := []string{"set", uid, money, date, end.Format("2006/01/02")}
    _, err := App.SetVVV(opera)
    if err != nil {
        fmt.Errorf("setMoney failed, err:%v\n", err)
        fmt.Fprintln(w, "失败！")
        return
    }
    sqlStr := "insert into transfer(uid, name, date, money) values (?,?,?,?)"
    err = initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
    }
    _, err = db.Exec(sqlStr, uid, name, date, money)
    if err != nil {
        fmt.Errorf("insert failed, err:%v\n", err)
    }
    fmt.Fprintln(w, "已将商品（商品序列号: " + cid + "）放入商城！")
}
func a_apply(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    cid := r.FormValue("uid")
    money := r.FormValue("money")
    money1 := r.FormValue("money1")
    num := r.FormValue("Num")
    cookie, _ :=r.Cookie("name")
    if num == "1"{
        var fd FileData
        opera := []string{"getFileDetail", name}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("get failed, err:%v\n", err)
        }
        err = json.Unmarshal([]byte(value), &fd)
        if err != nil {
            fmt.Errorf("Failed to json asset: %s", err)
        }

        fd.Flag = "buy"
        ShowView(w, r, "admin/cat.html", fd)
        return
    }
    var card string
    int1 ,err := strconv.Atoi(money)
    int2 ,err := strconv.Atoi(money1)
    if int1>int2{
        fmt.Fprintln(w, "小于起拍价格！")
        return
    }
    opera := []string{"getMoney", cookie.Value, money1}
    value, err := App.GetV(opera)
    if err != nil {
        fmt.Errorf("get failed, err:%v\n", err)
        opera = []string{"getMoney", cookie.Value, "-1"}
        value, _ = App.GetV(opera)
        fmt.Fprintln(w, "余额不足，请充值！当前余额为： "+value)
        return
    }
    err = initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
        return
    }
    sql := "SELECT name,card FROM user WHERE uid = '" + cookie.Value +"'"
    // fmt.Println(sql)
    //查询
    var username string
    err = db.QueryRow(sql).Scan(&username,&card)
    // fmt.Println(l.password)
    if err != nil {
        fmt.Println("login failed, err:%v\n", err)
    }

    priv := &ecdsa.PrivateKey{}
    opera = []string{"getTransaction", "K-"+cookie.Value}
    value, err = App.Get(opera)
    if err != nil {
        fmt.Errorf("get failed, err:%v\n", err)
    }
    err = json.Unmarshal([]byte(value), &priv)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
    }

    publicKeys := []*ecdsa.PublicKey{}
    opera = []string{"getTransaction", "Ring"}
    value, err = App.Get(opera)
    if err != nil {
        fmt.Errorf("get failed, err:%v\n", err)
    }
    err = json.Unmarshal([]byte(value), &publicKeys)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
    }
    publicKeys = append(publicKeys,&priv.PublicKey)


    var user User
    user.Id = cookie.Value
    user.Money = money1
    putData, err := json.Marshal(user)
    if err != nil {
    	fmt.Errorf("Failed to json2 asset: %s", err)
    }
    hash := MD5(string(putData))
    sig, err := SignRing([]byte(hash), priv, publicKeys)
    if err != nil {
    	fmt.Errorf("签名失败:", err)
    }
    putData, err = json.Marshal(sig)
    if err != nil {
        fmt.Errorf("Failed to json2 asset: %s", err)
    }

    opera = []string{"setTransaction", cookie.Value, cid, money1,string(putData)}
    value, err = App.SetVVV(opera)
    if err != nil {
        fmt.Errorf("get failed, err:%v\n", err)
    }

    fmt.Fprintln(w, "竞拍成功，等待结果公布！")
}
func a_detail(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    set := r.FormValue("Set")
    fmt.Println(name,set)
    var fd FileData
    //获取用户名字
    var ts []Transaction
    if set == "transfer"{
        opera := []string{"getTransaction", name}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("get failed, err:%v\n", err)
        }
        err = json.Unmarshal([]byte(value), &ts)
        if err != nil {
            fmt.Errorf("Failed to json asset: %s", err)
        }
        ShowView(w, r, "admin/transaction.html", ts)
    }else if set == "show"{
        opera := []string{"getFileDetail", name}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("get failed, err:%v\n", err)
        }
        err = json.Unmarshal([]byte(value), &fd)
        if err != nil {
            fmt.Errorf("Failed to json asset: %s", err)
        }
        fd.Flag = set
        ShowView(w, r, "admin/cat.html", fd)
    }else {
        opera := []string{"getFileDetail", name}
        value, err := App.Get(opera)
        if err != nil {
            fmt.Errorf("get failed, err:%v\n", err)
        }
        err = json.Unmarshal([]byte(value), &fd)
        if err != nil {
            fmt.Errorf("Failed to json asset: %s", err)
        }
        fd.Flag = set
        ShowView(w, r, "admin/cat.html", fd)
    }
}
func a_download(rw http.ResponseWriter,r *http.Request){
    //获取请求参数
    fn :=r.FormValue("filename")
    fp :=r.FormValue("filepath")
    data := CatIPFS(fn) //return []byte 文件字节流
    //设置响应头
    header:=rw.Header()
    header.Add("Content-Type","application/octet-stream")
    header.Add("Content-Disposition","attachment;filename="+fp)
    //写入到响应流中
    rw.Write([]byte(data))
}
//项目增加
func a_add(w http.ResponseWriter, r *http.Request) {
    names := r.FormValue("Name")
    if names == "edit"{
        id := r.FormValue("id")
        name := r.FormValue("name")
        detail := r.FormValue("detail")

        err := initDB()
        sqlStr := "UPDATE userDetail SET name='"+ name +"',detail='"+ detail +"' WHERE account = '" + id +"'"
        _, err = db.Exec(sqlStr)
        if err != nil {
            fmt.Errorf("edit failed, err:%v\n", err)
        }
        fmt.Println(id, name)
        fmt.Fprintln(w, "修改成功！")
        return
    }

    cookie, _:=r.Cookie("name")
    var fileData FileData
    ///获取其他值
    name := r.FormValue("name")
    detail := r.FormValue("detail")
    timess := r.FormValue("time")
    //文件处理
    r.ParseMultipartForm(32 << 20)
    file, handler, err := r.FormFile("file")
    filepath := handler.Filename
    fmt.Println(filepath)
    if err != nil {
        fmt.Fprintln(w, "上传失败！")
        fmt.Println(err)
        return
    }
    defer file.Close()
    fileContent, _ :=ioutil.ReadAll(file)
    fileData.FileHash = UploadIPFS(string(fileContent))
    times := strconv.FormatInt(time.Now().Unix(), 10)
    //对上传者的输入和区块链存储的hash值进行请求，如果返回fail，则验证失败
    fmt.Println("文件hash是", fileData.FileHash)

    //形成fileData
    fileData.CreateDate = time.Now().Format("2006/01/02 15:04:05")
    fileData.Date = time.Now().Format("2006/01/02 15:04:05")
    rands := time.Now().Format("2006/01/02 15:04:05") + strconv.Itoa(rand.Intn(100))
    fileData.Id = MD5(rands)
    fileData.Times = timess
    fileData.Filename = name
    //fileData.Card = r.FormValue("card")
    fileData.FileDetail = detail
    fileData.Filepath = filepath
    fileData.User = []string{cookie.Value}
    fileData.Time = times
    fileData.Flag = "未竞拍"
    fileData.Money1 = "---"
    fileData.Tmp = "未竞拍"

    r.ParseMultipartForm(32 << 20)
    file, handler, err = r.FormFile("files")
    filepath = handler.Filename
    fmt.Println(filepath)
    if err != nil {
        fmt.Fprintln(w, "上传失败！")
        fmt.Println(err)
        return
    }
    defer file.Close()
    fileContent, _ =ioutil.ReadAll(file)
    if err := ioutil.WriteFile("./web/static/img/"+fileData.Id, fileContent, 0666); err != nil {
        fmt.Fprintln(w, "错误！")
        fmt.Println(err)
        return
    }
    err = initDB()
    if err != nil {
        fmt.Println("init failed, err: %v\n", err)
        return
    }
    sql := "SELECT name FROM user WHERE uid = '" + cookie.Value +"'"
    err = db.QueryRow(sql).Scan(&fileData.Username)
    if err != nil {
        fmt.Errorf("select failed, err: %v\n", err)
    }
    //序列化
    putData, err := json.Marshal(fileData)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
        fmt.Fprintln(w, "上传失败！")
        return
    }
    //上传区块链文件
    opera := []string{"setFileData", string(putData), ""}
    _, err = App.Set(opera)
    if err != nil {
        fmt.Errorf("setFileData failed, err:%v\n", err)
        fmt.Fprintln(w, "上传失败！")
        return
    }
    fmt.Fprintln(w, "上传成功！")
}
func a_edit(w http.ResponseWriter, r *http.Request) {
    cookie,_:=r.Cookie("name")
    fmt.Println(cookie)
    var utd UserTmpDetail

    err := initDB()
    sql := "SELECT name, account, detail FROM userDetail WHERE id='"+ cookie.Value +"'"
    fmt.Println(sql)
    err = db.QueryRow(sql).Scan(&utd.Name,&utd.Id,&utd.Organization)
    if err != nil {
        ShowView(w, r, "admin/userEdit.html", utd)
        return
    }
    ShowView(w, r, "admin/userEdit.html", utd)
}

func aa_login(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    index := r.FormValue("index")
    //输入为空 则返回原页面
    if username == "" && index == "" {
        ShowView(w, r, "admin/admin/login.html", 0)
        //index也是返回原页面
    }else if index == "logout"{
        c := http.Cookie{
            Name: "name",
            Value: "",
        }
        //设置cookie
        http.SetCookie(w, &c)
        ShowView(w, r, "admin/admin/login.html", 0)
    }else if username == "admin" && password == "admin"{
        c := http.Cookie{
            Name: "name",
            Value: username,
        }
        //登录成功后 设置cookie
        http.SetCookie(w, &c)
        fmt.Fprintln(w, "1")
    }else {
        fmt.Fprintln(w, "2")
    }
}
func aa_index(w http.ResponseWriter, r *http.Request) {
    name, err := r.Cookie("name")
    if err != nil {
        ShowView(w, r, "admin/admin/403.html", nil)
        return
    } else if name.Value == ""{
        ShowView(w, r, "admin/admin/403.html", nil)
    } else {
        ShowView(w, r, "admin/admin/index.html", nil)
    }
}
func aa_verity(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    idCard := r.FormValue("id")
    tele := r.FormValue("tele")
    level := r.FormValue("level")
    var uid string
    err := initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
    }
    sql := "UPDATE user set Flag='Finish',card='" +idCard + "',name='" + name +"',level='" + level +"' WHERE username = '"+ tele +"'"
    _, err = db.Exec(sql)
    if err != nil {
        fmt.Println("UPDATE failed, err:%v\n", err)
    }

    sql = "SELECT uid FROM user WHERE username = '" + tele +"'"
    // fmt.Println(sql)
    //查询
    err = db.QueryRow(sql).Scan(&uid)
    if err != nil {
        fmt.Println("SELECT failed, err:%v\n", err)
    }

    priv, _ := ecdsa.GenerateKey(elliptic.P256(), ra.Reader)
    putData, err := json.Marshal(priv)
    if err != nil {
        fmt.Errorf("Failed to json asset: %s", err)
    }
    opera := []string{"setKey", "K-"+uid, string(putData)}
    _, err = App.Set(opera)
    if err != nil {
        fmt.Errorf("setKey failed, err:%v\n", err)
    }

    fmt.Fprintln(w, "添加成功！")
}
func aa_list(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    var utd UserTmpDetail
    err := initDB()
    if err != nil {
        fmt.Println("init failed, err:%v\n", err)
        return
    }
    defer db.Close()
    sql := "SELECT username,name, organization, card FROM user WHERE Flag='Unfinished' and uid = '"+ name +"'"
    err = db.QueryRow(sql).Scan(&utd.Flag, &utd.Name,&utd.Organization,&utd.IDCard)
    if err != nil{
        return
    }
    ShowView(w, r, "admin/admin/list.html", utd)
}
// 列表展示
func aa_user(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("Name")
    if name == "lists"{
        var utd UserTmpDetail
        var utds []UserTmpDetail
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        defer db.Close()
        sql := "SELECT uid, organization, name, card, Level FROM user"
        rows, err := db.Query(sql)
        if err != nil{
            return
        }
        for rows.Next() {
            err = rows.Scan(&utd.Id,&utd.Organization,&utd.Name,&utd.IDCard,&utd.Flag)
            if err != nil {
                fmt.Println(err)
            }
            utd.Flag=utd.Flag
            utds = append(utds, utd)
            fmt.Println(utd)
        }
        ShowView(w, r, "admin/admin/users.html", utds)
    }else if name == "verify"{
        var utd UserTmpDetail
        var utds []UserTmpDetail
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        defer db.Close()
        sql := "SELECT uid, username, name, card FROM user WHERE Flag='Unfinished'"
        rows, err := db.Query(sql)
        if err != nil{
            return
        }
        for rows.Next() {
            err = rows.Scan(&utd.Organization, &utd.Age, &utd.Name,&utd.IDCard)
            if err != nil {
                panic(err)
            }
            utds = append(utds, utd)
            fmt.Println(utd)
        }
        ShowView(w, r, "admin/admin/verify.html", utds)
    }
}
func aa_deletu(w http.ResponseWriter, r *http.Request){
    flag := r.FormValue("Flag")
    if flag == "user"{
        name := r.FormValue("Name")
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        sql := "DELETE FROM user WHERE uid = '"+ name +"'"
        _, err = db.Exec(sql)
        if err != nil {
            fmt.Println("delet failed, err:%v\n", err)
        }
        var utd UserTmpDetail
        var utds []UserTmpDetail
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        defer db.Close()
        sql = "SELECT uid, username, name, card, Level FROM user"
        rows, err := db.Query(sql)
        if err != nil{
            return
        }
        for rows.Next() {
            err = rows.Scan(&utd.Id,&utd.Organization,&utd.Name,&utd.IDCard,&utd.Flag)
            if err != nil {
                panic(err)
            }
            utds = append(utds, utd)
            fmt.Println(utd)
        }
        ShowView(w, r, "admin/admin/users.html", utds)
    }else {
        name := r.FormValue("tele")
        err := initDB()
        if err != nil {
            fmt.Println("init failed, err:%v\n", err)
            return
        }
        defer db.Close()
        sql := "UPDATE user set Flag='Again' WHERE username = '"+ name +"'"
        _, err = db.Exec(sql)
        if err != nil {
            fmt.Println("update failed, err:%v\n", err)
        }
        fmt.Fprintln(w, "操作成功！")
    }
}

// 生成环签名
func SignRing(message []byte, privKey *ecdsa.PrivateKey, publicKeys []*ecdsa.PublicKey) (*RingSignature, error) {
    n := len(publicKeys)
    if n == 0 {
        return nil, fmt.Errorf("至少需要一个公钥")
    }

    // 1. 计算消息哈希
    hash := sha256.Sum256(message)

    // 2. 找到签名者在环中的位置
    k := -1
    for i, pk := range publicKeys {
        if pk.X.Cmp(privKey.X) == 0 && pk.Y.Cmp(privKey.Y) == 0 {
            k = i
            break
        }
    }
    if k == -1 {
        return nil, fmt.Errorf("私钥未在公钥列表中")
    }

    curve := elliptic.P256()
    params := curve.Params()
    //nMinus1 := big.NewInt(int64(n - 1))

    // 3. 初始化参数
    s := make([]*big.Int, n)
    c := make([]*big.Int, n)

    // 4. 生成随机数v (实际应为k+1的挑战)
    v, _ := ra.Int(ra.Reader, params.N)
    c[(k+1)%n] = new(big.Int).SetBytes(hash[:])
    c[(k+1)%n].Mod(c[(k+1)%n], params.N)

    // 5. 前向计算环
    i := (k + 1) % n
    for i != k {
        // 生成随机s[i]
        s[i], _ = ra.Int(ra.Reader, params.N)

        // 计算下一挑战
        sGx, sGy := curve.ScalarBaseMult(s[i].Bytes())
        cPx, cPy := curve.ScalarMult(publicKeys[i].X, publicKeys[i].Y, c[i].Bytes())
        sumX, sumY := curve.Add(sGx, sGy, cPx, cPy)

        hashInput := append(sumX.Bytes(), sumY.Bytes()...)
        hashInput = append(hashInput, message...)
        nextHash := sha256.Sum256(hashInput)

        next := (i + 1) % n
        c[next] = new(big.Int).SetBytes(nextHash[:])
        c[next].Mod(c[next], params.N)

        i = (i + 1) % n
    }

    // 6. 关闭环
    s[k] = new(big.Int).Sub(v, new(big.Int).Mul(c[k], privKey.D))
    s[k].Mod(s[k], params.N)

    return &RingSignature{
        PublicKeys: publicKeys,
        C:          c[0],
        S:          s,
    }, nil
}
