import copy
import random


remap_table = ['6', '1', '0', '3', '7', '2', '5', '4',
               '5', '4', '3', '0', '6', '7', '2', '1',
               '6', '4', '5', '0', '3', '2', '1', '7',
               '0', '2', '7', '4', '6', '5', '3', '1',
               '1', '2', '4', '6', '3', '5', '0', '7',
               '7', '1', '3', '6', '0', '2', '5', '4',
               '3', '4', '0', '7', '6', '2', '1', '5',
               '3', '7', '4', '6', '0', '1', '2', '5',
               '2', '6', '4', '1', '0', '7', '5', '3',
               '1', '4', '0', '3', '7', '6', '2', '5',
               '7', '6', '1', '5', '3', '0', '4', '2',
               '3', '6', '0', '2', '7', '1', '5', '4',
               '7', '5', '1', '3', '6', '2', '4', '0',
               '1', '4', '0', '2', '5', '3', '6', '7',
               '3', '2', '7', '5', '1', '6', '4', '0',
               '6', '3', '7', '4', '0', '1', '5', '2']

hash_table = ['00', '20', '00', '04', '01', '00', '00', '02', '80', '00', '00', '08', '40', '00', '10', '00',
              '10', '04', '00', '00', '20', '40', '00', '80', '08', '01', '00', '00', '00', '02', '00', '00',
              '02', '00', '40', '20', '00', '00', '10', '00', '00', '01', '08', '80', '04', '00', '00', '00',
              '00', '80', '00', '10', '04', '00', '00', '20', '08', '00', '01', '00', '00', '00', '02', '40',
              '00', '00', '01', '00', '00', '40', '10', '00', '00', '02', '04', '00', '00', '08', '80', '20',
              '10', '00', '08', '00', '00', '02', '40', '00', '00', '00', '00', '04', '01', '20', '00', '80',
              '38', '68', '98', 'c8', '23', '4b', '73', '9b', '0c', '0a', '0c', '0a', '0a', '0c', '0a', '0c',
              '06', '01', '00', '03', '07', '02', '05', '04', '05', '04', '03', '00', '06', '07', '02', '01',
              '06', '04', '05', '00', '03', '02', '01', '07', '00', '02', '07', '04', '06', '05', '03', '01',
              '01', '02', '04', '06', '03', '05', '00', '07', '07', '01', '03', '06', '00', '02', '05', '04',
              '03', '04', '00', '07', '06', '02', '01', '05', '03', '07', '04', '06', '00', '01', '02', '05',
              '02', '06', '04', '01', '00', '07', '05', '03', '01', '04', '00', '03', '07', '06', '02', '05',
              '07', '06', '01', '05', '03', '00', '04', '02', '03', '06', '00', '02', '07', '01', '05', '04',
              '07', '05', '01', '03', '06', '02', '04', '00', '01', '04', '00', '02', '05', '03', '06', '07',
              '03', '02', '07', '05', '01', '06', '04', '00', '06', '03', '07', '04', '00', '01', '05', '02']


def password_remap(password):
    remap = []
    for n in range(0, 16):
        offset_multiplier = 8*n
        idx = 7
        while hex(password[n] - 1) != '0x' + remap_table[idx + offset_multiplier]:
            idx -= 1
        remap.append(idx)

    return remap


def password_hash(password):

    _1e96 = 15
    _1e8x = [0, 0, 0, 0, 0, 0]
    while _1e96 >= 0:
        _1e94_flag = False
        y = 0
        a = password[_1e96]
        for i in range(0, 5):
            a = a << 1
        _1e94 = a
        if _1e94 > 0:
            _1e94_flag = True
        for k in range(0, 3):
            a = 0
            while a == 0:
                a = y
                for i in range(0, 4):
                    a = (a << 1)
                a = a + _1e96
                x = a
                a = int('0x'+hash_table[x], 16)
                if a == 0:
                    y += 1

            x = y
            _1e94 = _1e94 << 1
            if _1e94 >= 256:
                _1e8x[x] = _1e8x[x] | a
                if not _1e94_flag:
                    _1e94 = 0
                else:
                    _1e94 = int(_1e94 & 0xFF)

            y += 1

        _1e96 -= 1

    return [hex(_1e8x[0]), hex(_1e8x[1]), hex(_1e8x[2]), hex(_1e8x[3]), hex(_1e8x[4]), hex(_1e8x[5])]


def hash_normalization(test_hex):

    _1e87 = test_hex[3]
    and_03 = hex(int(_1e87, 16) & int('0x03', 16))
    _1e94 = and_03

    for i in range(0, 4):
        and_03 = hex(int(and_03, 16) << 1)

    _1e94 = hex(int(and_03, 16) | int(_1e94, 16))
    _1e84 = test_hex[0]
    _1e84 = hex(int(_1e84, 16) ^ int(_1e94, 16))
    _1e85 = test_hex[1]
    _1e85 = hex(int(_1e85, 16) ^ int(_1e94, 16))
    _1e86 = test_hex[2]
    _1e86 = hex(int(_1e86, 16) ^ int(_1e94, 16))
    _1e89 = test_hex[5]
    _1e89 = hex(int(_1e89, 16) ^ int(_1e94, 16))
    _1e88 = test_hex[4]
    _1e88 = hex(int(_1e88, 16) ^ int(_1e94, 16))
    _1e87 = test_hex[3]

    return copy.copy([_1e84, _1e85, _1e86, _1e87, _1e88, _1e89])


def hash_subroutine(test_hex, index, n):

    zf = 0
    _1e94 = hex(int(test_hex[index], 16))
    _1e87 = test_hex[3]
    tmp = _1e87
    for i in range(0, n):
        tmp = hex(int(tmp, 16) >> 1)
    _1e95 = hex(int(tmp, 16) & int('0x01', 16))
    count_x = 0
    tmp = _1e94
    tmp, cf = hex(int(tmp, 16) >> 1), int(tmp, 16) & 1
    if cf == 1:
        count_x += 1
    while int(tmp, 16) != 0:
        tmp, cf = hex(int(tmp, 16) >> 1), int(tmp, 16) & 1
        if cf == 1:
            count_x += 1
    res1 = count_x ^ int(_1e95, 16)
    res2, cf = hex(res1 & int('0x1', 16)), int(hex(res1), 16) & 1
    if res2 == '0x0':
        zf = 1
    return zf


def hash_validation_1(test_hex):
    zf = hash_subroutine(test_hex, 0, 3)
    if zf == 1:
        zf = hash_subroutine(test_hex, 1, 4)
        if zf == 1:
            zf = hash_subroutine(test_hex, 2, 5)
            if zf == 1:
                zf = hash_subroutine(test_hex, 5, 6)
                if zf == 1:
                    zf = hash_subroutine(test_hex, 4, 7)
                    if zf == 1:
                        if (int(test_hex[5], 16) & int('0x40', 16)) == 0:
                            _1e94 = int(test_hex[5], 16) & int('0xbf', 16)
                            res = ((int(test_hex[0], 16) | int(test_hex[1], 16)) | _1e94) | int(test_hex[4], 16)
                            if res != 0:
                                return 'fail at second level analysis'
                            else:
                                return 'ok'
                        else:
                            last_test = int(test_hex[3], 16) & int('0x04', 16)
                            if last_test == 0:
                                return 'ok'
                            else:
                                return 'fail at third level analysis'
                    else:
                        return 'fail at index 4, 7'
                else:
                    return 'fail at index 5, 6'
            else:
                return 'fail at index 2, 5'
        else:
            return 'fail at index 1, 4'
    else:
        return 'fail at index 0, 3'


def fast_test(main_pass):
    remapped_pass = password_remap(main_pass)
    hash_result = password_hash(remapped_pass)
    hn = hash_normalization(hash_result)
    return hash_validation_1(copy.copy(hn))


def crunch_random():

    ok_count = 0
    ok_list = []
    a = 10000000
    b = 20000000
    print('range: ', a, b)

    for i in range(a, b):

        random.seed(i)
        main_pass = random.choices([1, 2, 3, 4, 5, 6, 7, 8], k=16)
        result = fast_test(copy.copy(main_pass))

        if i % 10000 == 0 and len(ok_list) > 0:
            print(str(ok_count) + ' found so far. - Last valid password: ' + str(ok_list[-1]))

        if result == 'ok':

            ok_count += 1
            ok_list.append(main_pass)

            if ok_count == 10000:
                out_file = open('/content/drive/My Drive/results/'+str(i) + '.txt', 'w')
                for t in ok_list:
                    line = ' '.join(str(x) for x in t)
                    out_file.write(line + '\n')
                out_file.close()
                ok_count = 0
                ok_list = []


print(fast_test([8, 4, 3, 4, 4, 2, 2, 4, 3, 3, 8, 6, 2, 7, 7, 3]))
print(fast_test([6, 1, 4, 1, 7, 8, 4, 5, 4, 4, 4, 7, 7, 6, 1, 5]))
print(fast_test([7, 7, 8, 4, 7, 4, 5, 2, 3, 3, 2, 1, 2, 3, 7, 1]))
print(fast_test([1, 6, 4, 8, 2, 8, 3, 4, 3, 1, 4, 1, 2, 2, 4, 1]))
print(fast_test([7, 3, 5, 7, 5, 3, 6, 3, 6, 4, 6, 2, 7, 8, 4, 1]))
crunch_random()
