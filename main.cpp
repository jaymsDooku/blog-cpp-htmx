#include <iostream>
#include <vector>
#include <chrono>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <sodium.h>

#include <SQLiteCpp/SQLiteCpp.h>
#include <SQLiteCpp/VariadicBind.h>

#include "maddy/parser.h"

#include "crow.h"

void create_default_config(const std::string& filename) {
    std::ofstream configFile(filename);
    if (configFile) {
        configFile << "[Admin]\n";
        configFile << "username = admin\n";
        configFile << "password = pass\n";
        configFile.close();
    } else {
        CROW_LOG_ERROR << "Could not create default config file.";
    }
}

char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

std::string decodeURIComponent(const std::string &input) {
    std::string decoded;
    for (std::size_t i = 0; i < input.size(); ++i) {
        char ch = input[i];
        if (ch == '%') {
            if (i + 2 < input.size()) {
                char hex1 = input[++i];
                char hex2 = input[++i];
                char decoded_char = from_hex(hex1) << 4 | from_hex(hex2);
                decoded += decoded_char;
            }
        } else {
            decoded += ch;
        }
    }
    return decoded;
}

std::map<std::string, std::string> read_body(const std::string& body) {
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::string> pairs;
    boost::split(pairs, body, boost::is_any_of("&"));

    std::map<std::string, std::string> body_map;
    for (const auto& element : pairs) {
        std::vector<std::string> pair;
        boost::split(pair, element, boost::is_any_of("="));
        body_map.emplace(pair[0], decodeURIComponent(pair[1]));
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    CROW_LOG_INFO << "Read Body (" << duration.count() << "us)";
    return body_map;
}

std::map<std::string, std::string> read_cookies(const std::string& cookieBody) {
    std::vector<std::string> cookieParts;
    boost::split(cookieParts, cookieBody, boost::is_any_of(";"));

    std::map<std::string, std::string> cookieMap;
    for (const auto& element : cookieParts) {
        std::vector<std::string> pair;
        boost::split(pair, element, boost::is_any_of("="));
        if (pair.size() == 2) {
            cookieMap.emplace(pair[0], pair[1]);
        } else if (pair.size() == 1) {
            cookieMap.emplace(pair[0], "true");
        }
    }
    return cookieMap;
}

std::string generate_token() {
    unsigned char buffer[32];
    randombytes_buf(buffer, sizeof(buffer));

    char hex_buffer[2 * sizeof(buffer) + 1];
    sodium_bin2hex(hex_buffer, sizeof(hex_buffer), buffer, sizeof(buffer));

    return {hex_buffer};
}

std::string get_authorization_token(const crow::request& req) {
    std::map<std::string, std::string> cookieMap = read_cookies(req.get_header_value("Cookie"));
    return cookieMap["Authorization"];
}

bool is_authorized(const crow::request& req, const std::string& token) {
    std::map<std::string, std::string> cookieMap = read_cookies(req.get_header_value("Cookie"));
    auto authorization = cookieMap["Authorization"];
    return (authorization == token);
}

std::string get_path_by_htmx(const crow::request& req, const std::string& filename) {
    return (req.get_header_value("htmx") == "true") ? filename + ".mustache" : filename + ".html";
}

std::string render(const std::string& path, crow::mustache::context& context) {
    return crow::mustache::compile(crow::mustache::load_text(path)).render_string(context);
}

std::string render(const std::string& path) {
    return crow::mustache::compile(crow::mustache::load_text(path)).render_string();
}

std::string render_page(const crow::request& req, const std::string& pagename) {
    std::string path = get_path_by_htmx(req, pagename);
    return render(path);
}

std::string render_page(const crow::request& req, const std::string& pagename, crow::mustache::context& context) {
    std::string path = get_path_by_htmx(req, pagename);
    return render(path, context);
}

std::string not_authorized(const crow::request& req) {
    std::string path = get_path_by_htmx(req, "not_authorized");
    return render(path);
}

std::string render_authorized_page(const crow::request& req, const std::string& admin_token, const std::string& pagename) {
    if (is_authorized(req, admin_token)) {
        std::string path = get_path_by_htmx(req, pagename);
        return render(path);
    } else {
        return not_authorized(req);
    }
}
std::string render_authorized_page(const crow::request& req, const std::string& admin_token, const std::string& pagename, crow::mustache::context& context) {
    if (is_authorized(req, admin_token)) {
        std::string path = get_path_by_htmx(req, pagename);
        return render(path, context);
    } else {
        return not_authorized(req);
    }
}

std::optional<crow::json::wvalue> get_post(SQLite::Database& db, int post_id, bool parseContent) {
    auto start = std::chrono::high_resolution_clock::now();
    crow::json::wvalue post;
    post["id"] = post_id;
    try {
        SQLite::Statement query(db, "SELECT title,content,creation_date FROM post WHERE id = ?");
        query.bind(1, post_id);

        if (query.executeStep()) {
            post["title"] = query.getColumn("title").getString();

            auto content = query.getColumn("content").getString();
            if (parseContent) {
                auto start = std::chrono::high_resolution_clock::now();

                std::stringstream contentStream(content);
                std::shared_ptr<maddy::Parser> parser = std::make_shared<maddy::Parser>();
                auto parsedContent = parser->Parse(contentStream);

                auto stop = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
                CROW_LOG_INFO << "Parsed Markdown (" << duration.count() << "ms)";

                post["content"] = parsedContent;
            } else {
                post["content"] = content;
            }
            post["creation_date"] = query.getColumn("creation_date").getString();
        }
    } catch (std::exception& e) {
        CROW_LOG_ERROR << "SQLite exception: " << e.what();
        return std::nullopt;
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    CROW_LOG_INFO << "Get Post (" << duration.count() << "ms)";
    return post;
}

std::string admin_token;

int main() {
    if (sodium_init() == -1) {
        return 1;
    }

    std::string configFilename = "config.ini";
    if (!std::filesystem::exists(configFilename)) {
        CROW_LOG_WARNING << "Config file not found. Creating default config...";
        create_default_config(configFilename);
    }

    boost::property_tree::ptree pt;
    try {
        boost::property_tree::ini_parser::read_ini(configFilename, pt);
    } catch (const boost::property_tree::ini_parser_error& e) {
        CROW_LOG_ERROR << "Error reading config file: " << e.what();
        return 1;
    }

    auto adminUsername = pt.get<std::string>("Admin.username");
    auto adminPasswordStr = pt.get<std::string>("Admin.password");
    const char* adminPassword = adminPasswordStr.c_str();
    char hashed_adminPassword[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hashed_adminPassword, adminPassword, strlen(adminPassword), crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN) != 0) {
        CROW_LOG_ERROR << "Out of memory when hashing password.";
        return 1;
    }

    CROW_LOG_INFO << "Admin Username: " << adminUsername;
    CROW_LOG_INFO << "Admin Password: " << adminPassword;

    SQLite::Database db("test.db", SQLite::OPEN_READWRITE|SQLite::OPEN_CREATE);
    db.exec("CREATE TABLE IF NOT EXISTS post(\n"
            "\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            "\ttitle TEXT,\n"
            "\tcontent TEXT,\n"
            "\tcreation_date DATETIME DEFAULT CURRENT_TIMESTAMP\n"
            ")");

    crow::SimpleApp app;
    crow::mustache::set_global_base("../templates");

    CROW_ROUTE(app, "/")([](const crow::request& req) {
        crow::mustache::context context;
        context["user"] = is_authorized(req, admin_token);
        return render("index.html", context);
    });

    CROW_ROUTE(app, "/posts")([&db]() {
        crow::mustache::context context;
        std::vector<crow::json::wvalue> posts;
        try {
            SQLite::Statement query(db, "SELECT id,title,content,creation_date FROM post");

            while (query.executeStep()) {
                const int id = query.getColumn("id");
                const char* title = query.getColumn("title");
                const char* content = query.getColumn("content");
                const char* creationDate = query.getColumn("creation_date");

                crow::json::wvalue post;
                post["id"] = id;
                post["title"] = title;
                post["content"] = content;
                post["creation_date"] = creationDate;
                posts.push_back(post);
            }
        } catch (std::exception& e) {
            CROW_LOG_ERROR << "SQLite exception: " << e.what();
            return crow::response(400);
        }
        context["posts"] = std::move(posts);

        return crow::response(200, render("posts.mustache", context));
    });

    CROW_ROUTE(app, "/post/<int>")([&db](const crow::request& req, int post_id) {
        std::optional<crow::json::wvalue> post = get_post(db, post_id, true);

        if (!post) {
            return crow::response(404);
        }

        crow::mustache::context context;
        context["post"] = std::move(*post);
        return crow::response(200, render_page(req, "post", context));
    });

    CROW_ROUTE(app, "/post/new")([](const crow::request& req) {
        return render_authorized_page(req, admin_token, "new_post");
    });

    CROW_ROUTE(app, "/post/edit/<int>")([&db](const crow::request& req, int post_id) {
        std::optional<crow::json::wvalue> post = get_post(db, post_id, false);
        if (!post) {
            return crow::response(404);
        }
        crow::mustache::context context;
        context["post"] = std::move(*post);
        auto success = crow::response(200, render_authorized_page(req, admin_token, "edit_post", context));
        return success;
    });

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

    CROW_ROUTE(app, "/post/<int>").methods(crow::HTTPMethod::PUT)([&db](const crow::request& req, int post_id) {
        if (!is_authorized(req, admin_token)) {
            return crow::response(401);
        }

        std::map<std::string, std::string> body_map = read_body(req.body);
        auto title = body_map["title"];
        auto content = body_map["content"];

        auto start = std::chrono::high_resolution_clock::now();
        try {
            SQLite::Statement updatePost(db, "UPDATE post SET title = ?, content = ? WHERE id = ?");
            updatePost.bind(1, title);
            updatePost.bind(2, content);
            updatePost.bind(3, post_id);
            updatePost.exec();
        } catch (std::exception& e) {
            CROW_LOG_ERROR << "SQLite Exception: " << e.what();
        }
        auto stop = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        CROW_LOG_INFO << "Update Post (" << duration.count() << "us)";

        CROW_LOG_INFO << "Post " << title << " has been edited.";
        CROW_LOG_INFO << "Redirecting to /post/" << post_id;

        crow::response success = crow::response(200);
        success.set_header("HX-Redirect", "/post/" + std::to_string(post_id));
        return success;
    });

    CROW_ROUTE(app, "/login")([](const crow::request& req) {
        std::string path = get_path_by_htmx(req, "login");
        return render(path);
    });
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([&db, &hashed_adminPassword](const crow::request& req) {
        std::map<std::string, std::string> body_map = read_body(req.body);

        auto username = body_map["username"];
        auto passwordStr = body_map["password"];
        const char* password = passwordStr.c_str();

        CROW_LOG_INFO << "Username: " << username;
        CROW_LOG_INFO << "Password: " << password;

        if (username == "admin" && crypto_pwhash_str_verify(hashed_adminPassword, password, strlen(password)) == 0) {
            CROW_LOG_INFO << "Admin logged in";
            admin_token = generate_token();

            crow::response success = crow::response(200);
            success.set_header("Set-Cookie", "Authorization=" + admin_token + "; Secure; HttpOnly");
            success.set_header("HX-Redirect", "/");
            return success;
        }

        return crow::response(400);
    });

    CROW_ROUTE(app, "/logout")([](const crow::request& req) {
        auto authorization_token = get_authorization_token(req);

        crow::response success = crow::response(200, render("logout.html"));
        success.set_header("Set-Cookie", "Authorization=" + authorization_token + "; Max-Age=-1; Secure; HttpOnly");
        success.set_header("HX-Redirect", "/logout");
        return success;
    });

    CROW_ROUTE(app, "/styles/<path>")
    ([&app](const std::string& path) {
        crow::response res;
        res.response::set_static_file_info_unsafe("../styles/" + path);
        return res;
    });

    CROW_ROUTE(app, "/img/<path>")
    ([&app](const std::string& path) {
        crow::response res;
        res.response::set_static_file_info_unsafe("../img/" + path);
        return res;
    });

    std::cout << "Hello, World!" << std::endl;
    app.port(18080).multithreaded().run();
    return 0;
}
