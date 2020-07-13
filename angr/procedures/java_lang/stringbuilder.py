import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.values import SimSootValue_StringRef

log = logging.getLogger(name=__name__)


class StringBuilderInit(JavaSimProcedure):

    __provides__ = (
        ('java.lang.StringBuilder', '<init>()'),
        ('java.lang.StringBuilder', '<init>(java.lang.String)'),
        ('java.lang.StringBuilder', '<init>(java.lang.CharSequence)'),
        ('java.lang.StringBuffer', '<init>()'),
        ('java.lang.StringBuffer', '<init>(java.lang.String)'),
        ('java.lang.StringBuffer', '<init>(java.lang.CharSequence)'),
    )

    def run(self, this_ref, thing=None):
        log.debug('Called SimProcedure java.lang.StringBuilder.<init> with args: {}'.format(this_ref))

        if thing:
            if isinstance(thing, SimSootValue_StringRef):
                thing_str = self.state.javavm_memory.load(thing)

            elif thing.type == 'java.lang.StringBuilder':
                thing_str_ref = thing.get_field(self.state, 'str', 'java.lang.String')
                thing_str = self.state.javavm_memory.load(thing_str_ref)

            else:
                log.error('NotImplemented, unsupported type for StringBuilder.<init>')
                thing_str = claripy.StringV('')

        else:
            thing_str = claripy.StringV('')

        str_ref = SimSootValue_StringRef.new_object(self.state, thing_str)
        this_ref.store_field(self.state, 'str', 'java.lang.String', str_ref)
        return


class StringBuilderAppend(JavaSimProcedure):

    __provides__ = (
        ('java.lang.StringBuilder', 'append(java.lang.String)'),
        ('java.lang.StringBuilder', 'append(int)'),
        ('java.lang.StringBuilder', 'append(long)'),
        ('java.lang.StringBuilder', 'append(boolean)'),
        ('java.lang.StringBuilder', 'append(char)'),
        ('java.lang.StringBuilder', 'append(java.lang.CharSequence)'),
        ('java.lang.StringBuffer', 'append(java.lang.String)'),
        ('java.lang.StringBuffer', 'append(int)'),
        ('java.lang.StringBuffer', 'append(long)'),
        ('java.lang.StringBuffer', 'append(boolean)'),
        ('java.lang.StringBuffer', 'append(char)'),
        ('java.lang.StringBuffer', 'append(java.lang.CharSequence)'),
    )

    def run(self, this_ref, thing):
        log.debug('Called SimProcedure java.lang.StringBuilder.append with args: {} {}'.format(this_ref, thing))
        field = this_ref.get_field(self.state, 'str', 'java.lang.String')
        field_str = self.state.javavm_memory.load(field)

        if isinstance(thing, SimSootValue_StringRef):
            thing_str = self.state.javavm_memory.load(thing)

        elif isinstance(thing, claripy.ast.BV):
            thing_str = claripy.IntToStr(thing)

        elif thing.type == 'java.lang.StringBuilder':
            thing_str_ref = thing.get_field(self.state, 'str', 'java.lang.String')
            thing_str = self.state.javavm_memory.load(thing_str_ref)

        else:
            log.error('NotImplemented, unsupported type for StringBuilder.append')
            return this_ref

        result = claripy.StrConcat(field_str, thing_str)
        new_str_ref = SimSootValue_StringRef.new_object(self.state, result)
        this_ref.store_field(self.state, 'str', 'java.lang.String', new_str_ref)

        return this_ref
