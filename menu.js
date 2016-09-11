function initMenu(relPath,searchEnabled,serverSide,searchPage,search) {
  function makeTree(data,relPath) {
    var result='';
    if ('children' in data) {
      result+='<ul>';
      for (var i in data.children) {
        result+='<li><a href="'+relPath+data.children[i].url+'">'+
                                data.children[i].text+'</a>'+
                                makeTree(data.children[i],relPath)+'</li>';
      }
      result+='</ul>';
    }
    return result;
  }

  $('#main-nav').append(makeTree(menudata,relPath));
  $('#main-nav').children(':first').addClass('sm sm-dox').attr('id','main-menu');
  if (searchEnabled) {
    if (serverSide) {
      $('#main-menu').append('<li style="float:right"><div id="MSearchBox" class="MSearchBoxInactive"><div class="left"><form id="FSearchBox" action="'+searchPage+'" method="get"><img id="MSearchSelect" src="'+relPath+'search/mag.png" alt=""/><input type="text" id="MSearchField" name="query" value="'+search+'" size="20" accesskey="S" onfocus="searchBox.OnSearchFieldFocus(true)" onblur="searchBox.OnSearchFieldFocus(false)"></form></div><div class="right"></div></div></li>');
    } else {
      $('#main-menu').append('<li style="float:right"><div id="MSearchBox" class="MSearchBoxInactive"><span class="left"><img id="MSearchSelect" src="'+relPath+'search/mag_sel.png" onmouseover="return searchBox.OnSearchSelectShow()" onmouseout="return searchBox.OnSearchSelectHide()" alt=""/><input type="text" id="MSearchField" value="'+search+'" accesskey="S" onfocus="searchBox.OnSearchFieldFocus(true)" onblur="searchBox.OnSearchFieldFocus(false)" onkeyup="searchBox.OnSearchFieldChange(event)"/></span><span class="right"><a id="MSearchClose" href="javascript:searchBox.CloseResultsWindow()"><img id="MSearchCloseImg" border="0" src="'+relPath+'search/close.png" alt=""/></a></span></div></li>');
    }
  }
  $('#main-menu').smartmenus();
}
