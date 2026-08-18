var a = new Uint8Array([1, 2, 3, 255]);
var b = new Int32Array(a.buffer);
print(a.length + "," + b.length);
