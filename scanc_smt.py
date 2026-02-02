
from parser import stpcommands
from ciphers.cipher import AbstractCipher


REVERSE_INOUT = True

PERM_INV = False

class ScanCCipher(AbstractCipher):
    name = "scanc"

    def getFormatString(self):
        """
        Format string used by the cryptosmt driver to print variables.
        """
        return ['P1', 'P2', 'P3', 'P4', 'wl', 'wr']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a differential characteristic for SCAN-C.
        Expects parameters to contain: wordsize (must be 16), rounds, sweight.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]


        f_weight_size = 48

        if wordsize != 16:
            print("SCAN-C uses 4x16-bit branches. Wordsize must be 16.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP (SCAN-C; scanc class enforced guards)\n"
                      "% SCAN-C w={} rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)


            p1 = ["P1{}".format(i) for i in range(rounds + 1)]
            p2 = ["P2{}".format(i) for i in range(rounds + 1)]
            p3 = ["P3{}".format(i) for i in range(rounds + 1)]
            p4 = ["P4{}".format(i) for i in range(rounds + 1)]

            ef_l = ["Efl{}".format(i) for i in range(rounds)]
            ef_r = ["Efr{}".format(i) for i in range(rounds)]


            s_out_l1_l = ["s_out_l1_l{}".format(i) for i in range(rounds)]
            p_out_l1_l = ["p_out_l1_l{}".format(i) for i in range(rounds)]
            s_out_l2_l = ["s_out_l2_l{}".format(i) for i in range(rounds)]
            p_out_l2_l = ["p_out_l2_l{}".format(i) for i in range(rounds)]

            s_out_l1_r = ["s_out_l1_r{}".format(i) for i in range(rounds)]
            p_out_l1_r = ["p_out_l1_r{}".format(i) for i in range(rounds)]
            s_out_l2_r = ["s_out_l2_r{}".format(i) for i in range(rounds)]
            p_out_l2_r = ["p_out_l2_r{}".format(i) for i in range(rounds)]

            wl = ["wl{}".format(i) for i in range(rounds)]
            wr = ["wr{}".format(i) for i in range(rounds)]


            stpcommands.setupVariables(stp_file, p1, wordsize)
            stpcommands.setupVariables(stp_file, p2, wordsize)
            stpcommands.setupVariables(stp_file, p3, wordsize)
            stpcommands.setupVariables(stp_file, p4, wordsize)

            stpcommands.setupVariables(stp_file, ef_l, wordsize)
            stpcommands.setupVariables(stp_file, ef_r, wordsize)

            stpcommands.setupVariables(stp_file, s_out_l1_l, wordsize)
            stpcommands.setupVariables(stp_file, p_out_l1_l, wordsize)
            stpcommands.setupVariables(stp_file, s_out_l2_l, wordsize)
            stpcommands.setupVariables(stp_file, p_out_l2_l, wordsize)

            stpcommands.setupVariables(stp_file, s_out_l1_r, wordsize)
            stpcommands.setupVariables(stp_file, p_out_l1_r, wordsize)
            stpcommands.setupVariables(stp_file, s_out_l2_r, wordsize)
            stpcommands.setupVariables(stp_file, p_out_l2_r, wordsize)


            stpcommands.setupVariables(stp_file, wl, f_weight_size)
            stpcommands.setupVariables(stp_file, wr, f_weight_size)


            all_weights = wl + wr
            stpcommands.setupWeightComputation(stp_file, weight, all_weights, f_weight_size)


            if rounds >= 1:
                stpcommands.assertNonZero(stp_file, [p1[1]], wordsize)
                stpcommands.assertNonZero(stp_file, [p2[1]], wordsize)
            if rounds >= 2:
                stpcommands.assertNonZero(stp_file, [p1[2]], wordsize)
                stpcommands.assertNonZero(stp_file, [p3[2]], wordsize)
            if rounds >= 1:
                stpcommands.assertNonZero(stp_file, [ef_l[0], ef_r[0]], wordsize)
                stpcommands.assertNonZero(stp_file, [s_out_l1_l[0], s_out_l2_l[0],
                                                     s_out_l1_r[0], s_out_l2_r[0]], wordsize)
            if rounds >= 1:
                stpcommands.assertNonZero(stp_file, [wl[0], wr[0]], f_weight_size)



            for i in range(rounds):
                self.setupScanCRound(stp_file,
                                     p1[i], p2[i], p3[i], p4[i],
                                     p1[i+1], p2[i+1], p3[i+1], p4[i+1],
                                     ef_l[i], ef_r[i], wl[i], wr[i],
                                     s_out_l1_l[i], p_out_l1_l[i],
                                     s_out_l2_l[i], p_out_l2_l[i],
                                     s_out_l1_r[i], p_out_l1_r[i],
                                     s_out_l2_r[i], p_out_l2_r[i],
                                     wordsize)


            all_state_vars = p1 + p2 + p3 + p4
            stpcommands.assertNonZero(stp_file, all_state_vars, wordsize)


            if parameters.get("iterative", False):
                stpcommands.assertVariableValue(stp_file, p1[0], p1[rounds])
                stpcommands.assertVariableValue(stp_file, p2[0], p2[rounds])
                stpcommands.assertVariableValue(stp_file, p3[0], p3[rounds])
                stpcommands.assertVariableValue(stp_file, p4[0], p4[rounds])


            for key, value in parameters.get("fixedVariables", {}).items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters.get("blockedCharacteristics", []):
                stpcommands.blockCharacteristic(stp_file, char, wordsize)


            stpcommands.setupQuery(stp_file)

        return

    def setupScanCRound(self, stp_file,
                        p1_in, p2_in, p3_in, p4_in,
                        p1_out, p2_out, p3_out, p4_out,
                        ef_l, ef_r, w_l, w_r,
                        s_out_l1_l, p_out_l1_l, s_out_l2_l, p_out_l2_l,
                        s_out_l1_r, p_out_l1_r, s_out_l2_r, p_out_l2_r,
                        wordsize):

        command = ""


        sP = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
              0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]
        sQ = [0x0, 0x8, 0x6, 0xD, 0x5, 0xF, 0x7, 0xC,
              0x4, 0xE, 0x2, 0x3, 0x9, 0x1, 0xB, 0xA]


        res = self.gen_sbox_stp(sP, p1_in, s_out_l1_l, w_l, 0, 0)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p1_in, s_out_l1_l, w_l, 1, 1)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p1_in, s_out_l1_l, w_l, 2, 2)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p1_in, s_out_l1_l, w_l, 3, 3)
        if res:
            command += res + "\n"
        command += self.perm_layer_stp(s_out_l1_l, p_out_l1_l) + "\n"


        res = self.gen_sbox_stp(sQ, p_out_l1_l, s_out_l2_l, w_l, 0, 4)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l1_l, s_out_l2_l, w_l, 1, 5)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l1_l, s_out_l2_l, w_l, 2, 6)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l1_l, s_out_l2_l, w_l, 3, 7)
        if res:
            command += res + "\n"
        command += self.perm_layer_stp(s_out_l2_l, p_out_l2_l) + "\n"


        res = self.gen_sbox_stp(sP, p_out_l2_l, ef_l, w_l, 0, 8)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l2_l, ef_l, w_l, 1, 9)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l2_l, ef_l, w_l, 2, 10)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l2_l, ef_l, w_l, 3, 11)
        if res:
            command += res + "\n"


        res = self.gen_sbox_stp(sP, p4_in, s_out_l1_r, w_r, 0, 0)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p4_in, s_out_l1_r, w_r, 1, 1)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p4_in, s_out_l1_r, w_r, 2, 2)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p4_in, s_out_l1_r, w_r, 3, 3)
        if res:
            command += res + "\n"
        command += self.perm_layer_stp(s_out_l1_r, p_out_l1_r) + "\n"

        res = self.gen_sbox_stp(sQ, p_out_l1_r, s_out_l2_r, w_r, 0, 4)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l1_r, s_out_l2_r, w_r, 1, 5)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l1_r, s_out_l2_r, w_r, 2, 6)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l1_r, s_out_l2_r, w_r, 3, 7)
        if res:
            command += res + "\n"
        command += self.perm_layer_stp(s_out_l2_r, p_out_l2_r) + "\n"

        res = self.gen_sbox_stp(sP, p_out_l2_r, ef_r, w_r, 0, 8)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l2_r, ef_r, w_r, 1, 9)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sP, p_out_l2_r, ef_r, w_r, 2, 10)
        if res:
            command += res + "\n"
        res = self.gen_sbox_stp(sQ, p_out_l2_r, ef_r, w_r, 3, 11)
        if res:
            command += res + "\n"


        command += "ASSERT({} = BVXOR({}, {}));\n".format(p1_out, ef_l, p3_in)

        command += "ASSERT({} = {});\n".format(p2_out, p1_in)

        command += "ASSERT({} = {});\n".format(p3_out, p4_in)

        command += "ASSERT({} = BVXOR({}, {}));\n".format(p4_out, ef_r, p2_in)

        stp_file.write(command)
        return

    def gen_sbox_stp(self, sbox, s_in, s_out, w,
                     nibble_pos, weight_pos):

        in_start = nibble_pos * 4
        out_start = nibble_pos * 4
        wt_start = weight_pos * 4

        variables = []
        if REVERSE_INOUT:

            for i in range(3, -1, -1):
                variables.append("{0}[{1}:{1}]".format(s_in, in_start + i))
            for i in range(3, -1, -1):
                variables.append("{0}[{1}:{1}]".format(s_out, out_start + i))
            for i in range(3, -1, -1):
                variables.append("{0}[{1}:{1}]".format(w, wt_start + i))
        else:

            for i in range(0, 4):
                variables.append("{0}[{1}:{1}]".format(s_in, in_start + i))
            for i in range(0, 4):
                variables.append("{0}[{1}:{1}]".format(s_out, out_start + i))
            for i in range(0, 4):
                variables.append("{0}[{1}:{1}]".format(w, wt_start + i))


        return stpcommands.add4bitSbox(sbox, variables)

    def perm_layer_stp(self, p_in, p_out):

        PERM_MAP = [0,1,4,5,2,3,8,9,6,7,12,13,10,11,14,15]

        if PERM_INV:
            inv = [0] * 16
            for idx, val in enumerate(PERM_MAP):
                inv[val] = idx
            map_to_use = inv
        else:
            map_to_use = PERM_MAP

        command = ""
        for out_bit in range(16):
            in_bit = map_to_use[out_bit]
            command += f"ASSERT({p_out}[{out_bit}:{out_bit}] = {p_in}[{in_bit}:{in_bit}]);\n"
        return command
