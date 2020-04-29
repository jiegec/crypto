#include "crypto.h"
#include <algorithm>

void bm(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  assert(input.size() > 0);
  // convert to number
  std::vector<size_t> a;
  for (int i = 0; i < input.size(); i++) {
    assert(input[i] == '0' || input[i] == '1');
    if (input[i] == '0') {
      a.push_back(0);
    } else if (input[i] == '1') {
      a.push_back(1);
    }
  }

  std::vector<std::vector<size_t>> f;
  std::vector<size_t> l;
  // f_0(x) = 1
  f.push_back(std::vector<size_t>{1});
  // l_0 = 0
  l.push_back(0);
  for (int n = 0; n < input.size(); n++) {
    size_t d_n = 0;
    for (int j = 0; j <= l[n]; j++) {
      d_n ^= f[n][j] * a[n - j];
    }
    if (d_n == 0) {
      // f_{n+1} = f_n
      f.push_back(f[n]);
      // l_{n+1} = l_n
      l.push_back(l[n]);
    } else {
      bool flag = true;
      for (int j = 0; j <= n; j++) {
        if (l[j] != 0) {
          flag = false;
          break;
        }
      }

      // if l_0=l_1=...=l_n=0
      if (flag) {
        // f_{n+1}(x) = 1+x^{n+1}
        std::vector<size_t> new_f;
        new_f.resize(n + 2);
        new_f[0] = 1;
        new_f[n + 1] = 1;
        f.push_back(new_f);
        // l_{n+1} = n+1
        l.push_back(n + 1);
      } else {
        // find m where l_m < l_{m+1} = l_{m+2} = ... = l_n
        for (int m = n - 1; m >= 0; m--) {
          if (l[m] < l[m + 1]) {
            // found
            // f_{n+1} = f_n + x^{n-m}*f_m
            std::vector<size_t> new_f;
            new_f.assign(f[n].begin(), f[n].end());
            new_f.resize(n + m);
            for (int j = 0; j < f[m].size(); j++) {
              new_f[n - m + j] ^= f[m][j];
            }
            f.push_back(new_f);
            // l_{n+1} = max{l_n, n+1-l_n}
            l.push_back(std::max(l[n], n + 1 - l[n]));
            break;
          }
        }
      }
    }
  }

  for (int i = 0; i < f.size(); i++) {
    assert(f[i][0] == 1);
    // skip one
    printf("f_%d: 1", i);
    for (int j = 1; j < f[i].size(); j++) {
      if (f[i][j]) {
        printf(" + x^%d", j);
      }
    }
    printf(" l_%d: %ld \n", i, l[i]);
  }

  output.clear();
  for (int i = 0; i < f[input.size()].size(); i++) {
    output.push_back(f[input.size()][i] + '0');
  }
  // strip trailing zeros
  while (output.size() > 0 && output[output.size()-1] == '0') {
    output.pop_back();
  }
}