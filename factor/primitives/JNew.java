/* :folding=explicit:collapseFolds=1: */

/*
 * $Id$
 *
 * Copyright (C) 2003, 2004 Slava Pestov.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * DEVELOPERS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package factor.primitives;

import factor.*;
import java.lang.reflect.*;
import java.util.Map;

public class JNew extends FactorPrimitiveDefinition
{
	//{{{ JNew constructor
	/**
	 * A new definition.
	 */
	public JNew(FactorWord word)
		throws Exception
	{
		super(word);
	} //}}}

	//{{{ eval() method
	public void eval(FactorInterpreter interp)
		throws Exception
	{
		FactorArray datastack = interp.datastack;
		Class clazz = FactorJava.toClass(datastack.pop());
		Cons args = (Cons)datastack.pop();
		Class[] _args = FactorJava.classNameToClassList(args);
		Constructor constructor = clazz.getConstructor(_args);

		Object[] params = new Object[_args.length];
		for(int i = params.length - 1; i >= 0; i--)
		{
			params[i] = FactorJava.convertToJavaType(
				datastack.pop(),_args[i]);
		}

		datastack.push(constructor.newInstance(params));
	} //}}}
}
