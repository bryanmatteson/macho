#include <typeinfo>

struct Root {
  virtual ~Root();
  virtual Root *clone() const;
  virtual int run() = 0;
};
struct Left : virtual Root {
  ~Left() override;
  Left *clone() const override;
  int run() override;
};
struct Right : virtual Root {
  ~Right() override;
  Right *clone() const override;
  int run() override;
};
struct Diamond final : Left, Right {
  ~Diamond() override;
  Diamond *clone() const override;
  int run() override;
};

Root::~Root() = default;
Root *Root::clone() const { return nullptr; }
Left::~Left() = default;
Left *Left::clone() const { return nullptr; }
int Left::run() { return 1; }
Right::~Right() = default;
Right *Right::clone() const { return nullptr; }
int Right::run() { return 2; }
Diamond::~Diamond() = default;
Diamond *Diamond::clone() const { return nullptr; }
int Diamond::run() { return 3; }

using MemberFunction = int (Diamond::*)();
extern "C" __attribute__((visibility("default"))) const std::type_info *rtti[] = {
    &typeid(Root), &typeid(Left), &typeid(Right), &typeid(Diamond),
    &typeid(Root *), &typeid(const Diamond *), &typeid(MemberFunction),
    &typeid(int[4]),
};
