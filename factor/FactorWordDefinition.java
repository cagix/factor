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

package factor;

import java.io.*;
import java.util.*;

/**
 * A word definition.
 */
public abstract class FactorWordDefinition
{
	public FactorWord word;

	//{{{ FactorWordDefinition constructor
	/**
	 * A new definition.
	 */
	public FactorWordDefinition(FactorWord word)
	{
		this.word = word;
	} //}}}

	public abstract void eval(FactorInterpreter interp)
		throws Exception;
	
	//{{{ fromList() method
	public void fromList(Cons cons)
		throws FactorRuntimeException
	{
		throw new FactorRuntimeException("Cannot unpickle " + this);
	} //}}}

	//{{{ toList() method
	public Cons toList()
	{
		return new Cons(new FactorWord(null,getClass().getName()),null);
	} //}}}

	//{{{ toString() method
	public String toString()
	{
		return getClass().getName() + ": " + word;
	} //}}}
}
