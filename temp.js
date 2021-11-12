const privateKey="-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFqwR02ooI6todIJJ66pcMZeyc\n2XpcwKQCgUf6bYmNZwAqP6rqxvZ/IzpfK6VH0PKc0AP0DIavFA3iyH6b8OQ4goff\nmGnpoeTQ/3Xzl4UYwi6lhvxggC1GE8GYagXNhnh7mCVa0Ixkx1QVhkAywcR+6lv+\nWX29ETQ99tjsXd0URQIDAQAB\n-----END PUBLIC KEY-----\n"
const buff = Buffer.from(privateKey).toString('base64');
const base64data = buff.toString('base64');
console.log(base64data);