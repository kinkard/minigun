@0xb3e21da9e66883ae;

# HTTP method enumeration
enum HttpMethod {
  get @0;
  post @1;
  put @2;
  delete @3;
  head @4;
  options @5;
  patch @6;
  trace @7;
}

# Individual HTTP request
struct HttpRequest {
  method @0 :HttpMethod;
  uri @1 :Text;
  # List of HTTP headers in "Key:Value" format
  headers @2 :List(Text);
  body @3 :Data;
}
