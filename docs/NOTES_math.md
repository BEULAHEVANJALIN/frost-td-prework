# Math notes

- Secret s = f(0). Share to j is s_j = f(j) over Z_q.
- Commitments: φ_k = a_k * G. Verify share: g^{s_j} == Σ j^k φ_k.
- Lagrange at 0: λ_i(0) = Π_{j≠i} (0 − j)/(i − j) mod q; s = Σ λ_i f(i).
- FROST partial: z_i = d_i + e_i p_i + λ_i s_i c (mod q); final z = Σ z_i; verify zG = R + cY.
