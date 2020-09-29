function epoch_to_local_time(utc) {
    var date = new Date(0); date.setUTCSeconds(utc);
    var year = date.getFullYear()
    var month = '0' + Number(date.getMonth() + 1).toString().substr(-2)
    var day = ('0' + date.getDate()).substr(-2)
    var hour = ('0' + date.getHours()).substr(-2)
    var minute = ('0' + date.getMinutes()).substr(-2)
    var second = ('0' + date.getSeconds()).substr(-2)
    var timezone = new Date().toLocaleTimeString('en-us',{timeZoneName:'short'}).split(' ')[2]
    return year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second + ' ' + timezone
}
