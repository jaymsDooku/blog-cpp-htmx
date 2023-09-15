Writing this Blog App in C++ with HTMX

This week I have been writing this Blog App in C++ with the help of HTMX on the frontend. Originally, I began writing this Blog App with a [Python Backend](https://github.com/jaymsDooku/blog-back) and [React Frontend](https://github.com/jaymsDooku/blog-front) - two technologies I'm familiar with. When I found out about HTMX, I joined the [HTMX discord](), and they have a list of channels for different backend-HTMX combos. In the cpp-htmx channel, I found [brakmic](https://blog.brakmic.com/) showcasing [CrowCpp-htmx](https://github.com/brakmic/htmx_server/tree/main). I've done a bit of C++ in the past with Visual Studio, but nothing related to web development, so I thought this project would be a fun way to learn some C++ and some HTMX.


## Setting Up Environment
In this project, I used CMake as my build system, Conan as my package manager, and CLion as my IDE. This made it really simple for me to add libraries to my project. Conan has a [plugin](https://plugins.jetbrains.com/plugin/11956-conan) for CLion, which I installed to add libraries quickly to my project. Conan will install the libraries for me, and I just have to add `find_package` and tell it to link with `target_link_libraries` in my CMakeLists.txt. One common criticism of C++ is how much of a faff it is to add libraries to a project, as you need to include header files and find the libraries to link, however CMake and Conan provide the easy plug-and-play workflow you get with libraries in other technologies like Python/Pip, Node/NPM, or Java/Gradle.

The libraries used in the project:

|table>
Name | About
- | - | -
CrowCpp   | Web framework      
libsodium | Cryptography  
maddy     | Markdown to HTML parser
SQLiteCpp | SQLite C++ Wrapper
|<table

## Configuration
My Blog App has a `config.ini`, which contains the username and password for the admin account. This `config.ini` is created by default in the working directory if it doesn't already exist. 

```
[Admin]
username = admin
password = pass
```

## Database
A SQLite database is used for storing posts data. There is only one table: `posts`.

|table>
Field Name | Field Type
- | - | -
id              | PK INTEGER
title           | TEXT
content         | TEXT
creation_date   | DATETIME
|<table


## CrowCpp
CrowCpp is a web framework, which offers a web server with an API to define routes, middleware, and templating (mustache).

### Routes
All routes of the Blog App can be found [here]().

In this article, we'll look at a single route - the create post - as it demonstrates quite a few essentials when it comes to exposing an endpoint for a web service. And the full code can be seen below.

```
CROW_ROUTE(app, "/post").methods(crow::HTTPMethod::POST)([&db](const crow::request& req) {
        if (!is_authorized(req, admin_token)) {
            return crow::response(401);
        }

        std::map<std::string, std::string> body_map = read_body(req.body);
        auto title = body_map["title"];
        auto content = body_map["content"];

        long long post_id = -1;

        try {
            SQLite::Statement insertPost(db, "INSERT INTO post (title, content) VALUES (?, ?)");
            insertPost.bind(1, title);
            insertPost.bind(2, content);
            insertPost.exec();

            post_id = db.getLastInsertRowid();
        } catch (std::exception& e) {
            CROW_LOG_ERROR << "SQLite Exception: " << e.what();
        }
        CROW_LOG_INFO << "Post " << title << " has been created.";
        CROW_LOG_INFO << "Redirecting to /post/" << post_id;

        crow::response success = crow::response(200);
        success.set_header("HX-Redirect", "/post/" + std::to_string(post_id));
        return success;
    });
```

Looking at the first line, we define a route with the `CROW_ROUTE` macro, providing an instance of the app and the endpoint path. We can then define what methods work with this route, and finally begin writing a lambda handler, where a reference to the database is given and the received request is passed as a parameter.

```
CROW_ROUTE(app, "/post").methods(crow::HTTPMethod::POST)([&db](const crow::request& req) {
```

Form data is sent to this route from a 'new post' form. In order to read this form data, the request's body is passed into `read_body`, and this returns a map, from which we can pull field data from.

```
std::map<std::string, std::string> body_map = read_body(req.body);
auto title = body_map["title"];
auto content = body_map["content"];
```

Next we insert the post data into the database with a simple insert statement. SQLiteCpp offers an API to prepare statements and retrieve the last inserted row id.

```
try {
    SQLite::Statement insertPost(db, "INSERT INTO post (title, content) VALUES (?, ?)");
    insertPost.bind(1, title);
    insertPost.bind(2, content);
    insertPost.exec();

    post_id = db.getLastInsertRowid();
} catch (std::exception& e) {
    CROW_LOG_ERROR << "SQLite Exception: " << e.what();
}
```

Finally, we can use that last inserted row id to redirect the user to the post's page.

```
crow::response success = crow::response(200);
success.set_header("HX-Redirect", "/post/" + std::to_string(post_id));
return success;
```
