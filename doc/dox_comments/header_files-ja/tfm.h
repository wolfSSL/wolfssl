/*!
    \ingroup Math

    \brief この関数は、整数の最大サイズに関するランタイムfastmath設定をチェックします。ユーザーがwolfCryptライブラリを独立して使用している場合に重要です。数学が正しく動作するためには、各ライブラリのFP_SIZEが一致している必要があります。このチェックはCheckFastMathSettings()として定義されており、CheckRunTimeFastMathとFP_SIZEを単純に比較し、不一致の場合は0を、一致する場合は1を返します。

    \return FP_SIZE 数学ライブラリで使用可能な最大サイズに対応するFP_SIZEを返します。

    \param none パラメータなし。

    _Example_
    \code
    if (CheckFastMathSettings() != 1) {
	    return err_sys("Build vs. runtime fastmath FP_MAX_BITS mismatch\n");
    }
    // これはプリプロセッサによって次のように変換されます:
    // if ( (CheckRunTimeFastMath() == FP_SIZE) != 1) {
    // そしてfastmath設定がコンパイル時の設定と一致することを確認します
    \endcode

    \sa CheckRunTimeSettings
*/
word32 CheckRunTimeFastMath(void);
