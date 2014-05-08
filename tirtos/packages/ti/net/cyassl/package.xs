/*
 *  ======== package.xs ========
 */

/*
 *  ======== getLibs ========
 *  Contribute CyaSSL library.
 */
function getLibs(prog) 
{
    return ("lib/" + this.$name + ".a" + prog.build.target.suffix);
}
