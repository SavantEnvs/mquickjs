var r = /a(b+)c/i;
var m = "xxABBBCxx".match(r);
print(m ? m[1] : "no match");
