import collections
import claripy

class SimVariable(object):

    __slots__ = ['ident', 'name', 'region']

    def __init__(self, ident=None, name=None, region=None):
        """
        :param ident: A unique identifier provided by user or the program. Usually a string.
        :param str name: Name of this variable.
        """
        self.ident = ident
        self.name = name
        self.region = region if region is not None else ""

    @property
    def phi(self):
        return False


class SimConstantVariable(SimVariable):

    __slots__ = ['value', '_hash']

    def __init__(self, ident=None, value=None, region=None):
        super(SimConstantVariable, self).__init__(ident=ident, region=region)
        self.value = value
        self._hash = None

    def __repr__(self):
        s = "<%s|const %s>" % (self.region, self.value)

        return s

    def __eq__(self, other):
        if not isinstance(other, SimConstantVariable):
            return False

        if self.value is None or other.value is None:
            # they may or may not represent the same constant. return not equal to be safe
            return False

        return self.ident == other.ident and self.value == other.value and self.region == other.region

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(('const', self.value, self.ident, self.region, self.ident))
        return self._hash


class SimTemporaryVariable(SimVariable):

    __slots__ = ['tmp_id', '_hash']

    def __init__(self, tmp_id):
        SimVariable.__init__(self)

        self.tmp_id = tmp_id
        self._hash = None

    def __repr__(self):
        s = "<tmp %d>" % (self.tmp_id)

        return s

    def __hash__(self):
        if self._hash is None:
            self._hash = hash('tmp_%d' % (self.tmp_id))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimTemporaryVariable):
            return hash(self) == hash(other)

        return False


class SimRegisterVariable(SimVariable):

    __slots__ = ['reg', 'size', '_hash']

    def __init__(self, reg_offset, size, ident=None, name=None, region=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region)

        self.reg = reg_offset
        self.size = size
        self._hash = None

    def __repr__(self):

        ident_str = "[%s]" % self.ident if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, (int, long)) else self.region
        phi_str = ("phi(%s)|" % (",".join(v.ident for v in self.variables))) if self.phi else ""  #pylint:disable=no-member

        s = "<%s%s%s|Reg %s, %sB>" % (phi_str, region_str, ident_str, self.reg, self.size)

        return s

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(('reg', self.region, self.reg, self.size, self.ident))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimRegisterVariable):
            return self.ident == other.ident and \
                   self.name == other.name and \
                   self.reg == other.reg and \
                   self.size == other.size and \
                   self.region == other.region and \
                   self.phi == other.phi

        return False


class SimRegisterVariablePhi(SimRegisterVariable):

    __slots__ = ['variables', '_hash']

    def __init__(self, ident=None, name=None, region=None, variables=None):
        var = next(iter(variables))
        reg_offset = var.reg
        size = var.size

        super(SimRegisterVariablePhi, self).__init__(reg_offset, size, ident=ident, name=name, region=region)

        self.variables = set(variables)
        self._hash = None

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.name, self.region, self.size, self.ident, tuple(self.variables)))
        return self._hash

    def __eq__(self, other):
        if type(other) is not SimRegisterVariablePhi:
            return False

        return self.ident == other.ident and \
               self.variables == other.variables and \
               self.name == other.name and \
               self.region == other.region and \
               self.size == other.size

    @property
    def phi(self):
        return True


class SimMemoryVariable(SimVariable):

    __slots__ = ['addr', 'size', '_hash']

    def __init__(self, addr, size, ident=None, name=None, region=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region)

        self.addr = addr

        if isinstance(size, claripy.ast.BV) and not size.symbolic:
            # Convert it to a concrete number
            size = size._model_concrete.value

        self.size = size
        self._hash = None

    def __repr__(self):
        if type(self.size) in (int, long):
            size = '%d' % self.size
        else:
            size = '%s' % self.size

        if type(self.addr) in (int, long):
            s = "<%s|Mem %#x %s>" % (self.region, self.addr, size)
        else:
            s = "<%s|Mem %s %s>" % (self.region, self.addr, size)

        return s

    def __hash__(self):
        if self._hash is not None:
            return self._hash

        if isinstance(self.addr, AddressWrapper):
            addr_hash = hash(self.addr)
        elif type(self.addr) in (int, long):
            addr_hash = self.addr
        elif self.addr._model_concrete is not self.addr:
            addr_hash = hash(self.addr._model_concrete)
        elif self.addr._model_vsa is not self.addr:
            addr_hash = hash(self.addr._model_vsa)
        elif self.addr._model_z3 is not self.addr:
            addr_hash = hash(self.addr._model_z3)
        else:
            addr_hash = hash(self.addr)
        self._hash = hash((addr_hash, hash(self.size), self.ident))

        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimMemoryVariable):
            return self.ident == other.ident and \
                   self.addr == other.addr and \
                   self.name == other.name and \
                   self.size == other.size and \
                   self.phi == other.phi

        return False


class SimMemoryVariablePhi(SimMemoryVariable):

    __slots__ = ['variables', '_hash']

    def __init__(self, ident=None, name=None, region=None, variables=None):
        var = next(iter(variables))
        addr = var.addr
        size = var.size

        super(SimMemoryVariablePhi, self).__init__(addr, size, ident=ident, name=name, region=region)

        self.variables = set(variables)
        self._hash = None

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.name, self.region, self.size, self.ident, tuple(self.variables)))
        return self._hash

    def __eq__(self, other):
        if type(other) is not SimMemoryVariablePhi:
            return False

        return self.ident == other.ident and \
               self.variables == other.variables and \
               self.addr == other.addr and \
               self.name == other.name and \
               self.region == other.region and \
               self.size == other.size

    @property
    def phi(self):
        return True


class SimStackVariable(SimMemoryVariable):

    __slots__ = ['base', 'offset']

    def __init__(self, offset, size, base='sp', base_addr=None, ident=None, name=None, region=None):
        if offset > 0x1000000 and isinstance(offset, (int, long)):
            # I don't think any positive stack offset will be greater than that...
            # convert it to a negative number
            mask = (1 << offset.bit_length()) - 1
            offset = - ((0 - offset) & mask)

        if base_addr is not None:
            addr = offset + base_addr
        else:
            # TODO: this is not optimal
            addr = offset

        super(SimStackVariable, self).__init__(addr, size, ident=ident, name=name, region=region)

        self.base = base
        self.offset = offset

    def __repr__(self):
        if type(self.size) in (int, long):
            size = '%d' % self.size
        else:
            size = '%s' % self.size

        prefix = "%s(stack)" % self.name if self.name is not None else "Stack"
        ident = "[%s]" % self.ident if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, (int, long)) else self.region
        phi_str = "phi|" if self.phi else ""

        if type(self.offset) in (int, long):
            if self.offset < 0:
                offset = "%#x" % self.offset
            elif self.offset > 0:
                offset = "+%#x" % self.offset
            else:
                offset = ""

            s = "<%s%s%s|%s %s%s, %s B>" % (phi_str, region_str, ident, prefix, self.base, offset, size)
        else:
            s = "<%s%s%s|%s %s%s, %s B>" % (phi_str, region_str, ident, prefix, self.base, self.addr, size)

        return s

    def __eq__(self, other):
        if type(other) is not SimStackVariable:
            return False

        return self.ident == other.ident and \
               self.name == other.name and \
               self.base == other.base and \
               self.offset == other.offset and \
               self.size == other.size and \
               self.phi == other.phi


class SimStackVariablePhi(SimStackVariable):

    __slots__ = ['variables', '_hash']

    def __init__(self, ident=None, name=None, region=None, variables=None):
        var = next(iter(variables))
        offset = var.addr
        size = var.size

        super(SimStackVariablePhi, self).__init__(offset, size, ident=ident, name=name, region=region)

        self.variables = set(variables)
        self._hash = None

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.name, self.region, self.size, self.ident, tuple(self.variables)))
        return self._hash

    def __eq__(self, other):
        if type(other) is not SimStackVariablePhi:
            return False

        return self.ident == other.ident and \
               self.variables == other.variables and \
               self.addr == other.addr and \
               self.name == other.name and \
               self.region == other.region and \
               self.size == other.size

    @property
    def phi(self):
        return True


class SimVariableSet(collections.MutableSet):
    """
    A collection of SimVariables.
    """

    def __init__(self):

        self.register_variables = set()
        # For the sake of performance optimization, all elements in register_variables must be concrete integers which
        # representing register offsets..
        # There shouldn't be any problem apart from GetI/PutI instructions. We simply ignore them for now.
        # TODO: Take care of register offsets that are not aligned to (arch.bits/8)
        # TODO: arch.bits/what? That number has no power here anymore.
        self.register_variable_offsets = set()

        # memory_variables holds SimMemoryVariable objects
        self.memory_variables = set()
        # For the sake of performance, we have another set that stores memory addresses of memory_variables
        self.memory_variable_addresses = set()

    def add(self, item):
        if type(item) is SimRegisterVariable:
            if not self.contains_register_variable(item):
                self.add_register_variable(item)
        elif type(item) is SimMemoryVariable:
            if not self.contains_memory_variable(item):
                self.add_memory_variable(item)
        else:
            # TODO:
            raise Exception('WTF')

    def add_register_variable(self, reg_var):
        self.register_variables.add(reg_var)
        self.register_variable_offsets.add(reg_var.reg)

    def add_memory_variable(self, mem_var):
        self.memory_variables.add(mem_var)
        base_address = mem_var.addr.address # Dealing with AddressWrapper
        for i in xrange(mem_var.size):
            self.memory_variable_addresses.add(base_address + i)

    def discard(self, item):
        if type(item) is SimRegisterVariable:
            if self.contains_register_variable(item):
                self.discard_register_variable(item)
        elif isinstance(item, SimMemoryVariable):
            if self.contains_memory_variable(item):
                self.discard_memory_variable(item)
        else:
            # TODO:
            raise Exception('')

    def discard_register_variable(self, reg_var):
        self.register_variables.remove(reg_var)
        self.register_variable_offsets.remove(reg_var.reg)

    def discard_memory_variable(self, mem_var):
        self.memory_variables.remove(mem_var)
        for i in xrange(mem_var.size):
            self.memory_variable_addresses.remove(mem_var.addr.address + i)

    def __len__(self):
        return len(self.register_variables) + len(self.memory_variables)

    def __iter__(self):
        for i in self.register_variables: yield i
        for i in self.memory_variables: yield i

    def add_memory_variables(self, addrs, size):
        for a in addrs:
            var = SimMemoryVariable(a, size)
            self.add_memory_variable(var)

    def copy(self):
        s = SimVariableSet()
        s.register_variables |= self.register_variables
        s.register_variable_offsets |= self.register_variable_offsets
        s.memory_variables |= self.memory_variables
        s.memory_variable_addresses |= self.memory_variable_addresses

        return s

    def complement(self, other):
        """
        Calculate the complement of `self` and `other`.

        :param other:   Another SimVariableSet instance.
        :return:        The complement result.
        """

        s = SimVariableSet()
        s.register_variables = self.register_variables - other.register_variables
        s.register_variable_offsets = self.register_variable_offsets - other.register_variable_offsets
        s.memory_variables = self.memory_variables - other.memory_variables
        s.memory_variable_addresses = self.memory_variable_addresses - other.memory_variable_addresses

        return s

    def contains_register_variable(self, reg_var):
        reg_offset = reg_var.reg
        # TODO: Make sure reg_offset is aligned to machine-word length

        return reg_offset in self.register_variable_offsets

    def contains_memory_variable(self, mem_var):
        a = mem_var.addr
        if type(a) in (tuple, list): a = a[-1]

        return a in self.memory_variable_addresses

    def __ior__(self, other):
        # other must be a SimVariableSet
        self.register_variables |= other.register_variables
        self.register_variable_offsets |= other.register_variable_offsets
        self.memory_variables |= other.memory_variables
        self.memory_variable_addresses |= other.memory_variable_addresses

    def __contains__(self, item):
        if type(item) is SimRegisterVariable:

            return self.contains_register_variable(item)

        elif type(item) is SimMemoryVariable:
            # TODO: Make it better!
            return self.contains_memory_variable(item)

        else:
            __import__('ipdb').set_trace()
            raise Exception("WTF is this variable?")

from .storage.memory import AddressWrapper
