function make_counter() {
    var n = 0;
    return function() { return n++; };
}
var c = make_counter();
print(c() + "," + c() + "," + c());
