// C++ fixture with exceptions (.eh_frame/.gcc_except_table), virtual
// calls, templates and mangled names.
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

struct Shape {
    virtual ~Shape() = default;
    virtual double area() const = 0;
};
struct Rect : Shape {
    double w, h;
    Rect(double w, double h) : w(w), h(h) {}
    double area() const override { return w * h; }
};
struct Circle : Shape {
    double r;
    explicit Circle(double r) : r(r) {}
    double area() const override { return 3.14159 * r * r; }
};

template <typename T> T checked_sum(const std::vector<T> &v) {
    T s{};
    for (auto &x : v) {
        if (x < T{}) throw std::runtime_error("negative element");
        s += x;
    }
    return s;
}

int main(int argc, char **) {
    std::vector<Shape *> shapes{new Rect(2, 3), new Circle(1.5)};
    double total = 0;
    for (auto *s : shapes) total += s->area();
    try {
        std::vector<int> v{1, 2, argc - 3};
        std::printf("%d\n", checked_sum(v));
    } catch (const std::exception &e) {
        std::printf("caught: %s\n", e.what());
    }
    for (auto *s : shapes) delete s;
    std::printf("%f\n", total);
    return 0;
}
